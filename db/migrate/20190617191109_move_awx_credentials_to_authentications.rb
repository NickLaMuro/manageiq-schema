class MoveAwxCredentialsToAuthentications < ActiveRecord::Migration[5.0]
  class Authentication < ActiveRecord::Base
    include ActiveRecord::IdRegions
    self.inheritance_column = :_type_disabled
    serialize :options
  end

  class Fernet256
    attr_reader :hmac, :cipher, :signing_key, :encryption_key

    InvalidToken = Class.new(ArgumentError)

    def initialize(key)
      decoded_key = Base64.urlsafe_decode64(key)
      if decoded_key.size != 64
        raise ArgumentError, "Fernet key must be 64 url-safe base64-encoded bytes."
      end

      @signing_key    = decoded_key[0,32]
      @encryption_key = decoded_key[32,32]

      @cipher = OpenSSL::Cipher::AES256.new(:CBC)
      @hmac   = OpenSSL::HMAC.new signing_key, OpenSSL::Digest::SHA256.new
    end

    def decrypt(token)
      data = Base64.urlsafe_decode64(token)
      verify data

      cipher.decrypt
      cipher.iv  = data[9,16]
      cipher.key = encryption_key
      ciphertext = data[25..-33]

      decrypted  = cipher.update ciphertext
      decrypted << cipher.final
    end

    private

    def verify(data)
      hmac << data[0..-33]
      signature = data[-32..-1]
      return if hmac.digest == signature
      raise InvalidToken
    end
  end

  class AnsibleDecrypt
    attr_reader :encryption_key, :encrypted_data

    def self.decrypt(field_name, value, primary_key)
      require 'openssl'
      require 'base64'

      return value unless value.include?("$encrypted$")

      new(secret_key, value, field_name, primary_key).decrypt
    end

    def self.secret_key
      @secret_key ||= begin
        key = Authentication.find_by(
          :resource_id   => MiqDatabase.first.id,
          :resource_type => "MiqDatabase",
          :name          => "Ansible Secret Key",
          :authtype      => "ansible_secret_key",
          :type          => "AuthToken"
        ).auth_key
        ManageIQ::Password.decrypt(key)
      end
    end

    def initialize(secret_key, value, field_name, primary_key)
      @encryption_key = get_encryption_key(secret_key, field_name, primary_key)
      @encrypted_data = parse_raw_data(value)
    end

    def decrypt
      Fernet256.new(encryption_key).decrypt(encrypted_data).chomp
    end

    private

    def get_encryption_key(secret, field, pk=nil)
      key_hash  = OpenSSL::Digest::SHA512.new
      key_hash << secret
      key_hash << pk if pk
      key_hash << field
      Base64.urlsafe_encode64(key_hash.digest)
    end

    def parse_raw_data(value)
      raw_data = value[11..-1]
      raw_data = raw_data[5..-1] if raw_data.start_with?('UTF8$')

      algorithm, base64_data = raw_data.split('$', 2)

      if algorithm != 'AESCBC'
        raise Fernet256::InvalidToken, "unsupported algorithm: #{algorithm}"
      end

      Base64.decode64(base64_data)
    end
  end

  class MiqDatabase < ActiveRecord::Base; end

  ENCRYPTED_ATTRIBUTES = %w[
    auth_key
    auth_key_password
    become_password
    password
  ].freeze

  FIELD_MAP = {
    'authorize_password' => 'become_password',
    'become_username'    => 'become_username',
    'become_password'    => 'become_password',
    'password'           => 'password',
    'secret'             => 'auth_key',
    'security_token'     => 'auth_key',
    'ssh_key_data'       => 'auth_key',
    'ssh_key_unlock'     => 'auth_key_password',
    'username'           => 'userid',
    'vault_password'     => 'password'
  }.freeze

  OPTIONS_FIELDS = %w[
    authorize
    become_method
    client
    domain
    host
    project
    subscription
    tenant
  ].freeze

  def up
    embedded_ansible_authentications.each do |auth|
      if auth.manager_ref.nil?
        say("Skipping authentication #{auth.id} with nil manager ref")
        next
      end

      say_with_time("Migrating credential #{auth.name} from awx to vmdb") do
        awx_info = awx_credential_info(auth.manager_ref)
        update_authentication(auth, awx_info)
      end
    end
  rescue PG::ConnectionBad
    say("awx database is unreachable, credentials cannot be migrated")
  end

  private

  def embedded_ansible_authentications
    types = %w[
      ManageIQ::Providers::EmbeddedAnsible::AutomationManager::Credential
      ManageIQ::Providers::EmbeddedAnsible::AutomationManager::CloudCredential
      ManageIQ::Providers::EmbeddedAnsible::AutomationManager::MachineCredential
      ManageIQ::Providers::EmbeddedAnsible::AutomationManager::NetworkCredential
      ManageIQ::Providers::EmbeddedAnsible::AutomationManager::ScmCredential
      ManageIQ::Providers::EmbeddedAnsible::AutomationManager::VaultCredential
      ManageIQ::Providers::EmbeddedAnsible::AutomationManager::AmazonCredential
      ManageIQ::Providers::EmbeddedAnsible::AutomationManager::AzureCredential
      ManageIQ::Providers::EmbeddedAnsible::AutomationManager::GoogleCredential
      ManageIQ::Providers::EmbeddedAnsible::AutomationManager::OpenstackCredential
      ManageIQ::Providers::EmbeddedAnsible::AutomationManager::RhvCredential
      ManageIQ::Providers::EmbeddedAnsible::AutomationManager::VmwareCredential
    ]
    Authentication.in_my_region.where(:type => types)
  end

  def awx_credential_info(awx_id)
    cred_info = awx_connection.async_exec("SELECT inputs FROM main_credential WHERE id = $1::BIGINT", [awx_id]).first
    # in case there is no matching credential on the awx side
    return {} unless cred_info

    JSON.parse(cred_info["inputs"])
  end

  def awx_connection
    @awx_connection ||= PG::Connection.new(ApplicationRecord.connection.raw_connection.conninfo_hash.merge(:dbname => "awx").delete_blanks)
  end

  def update_authentication(auth, awx_info)
    auth.options = auth.options.slice(*OPTIONS_FIELDS.map(&:to_sym)).presence if auth.options

    awx_info.each do |k, v|
      if OPTIONS_FIELDS.include?(k)
        auth.options ||= {}
        auth.options[k.to_sym] = v
        next
      end

      authentication_attribute = FIELD_MAP[k]
      decrypted_value          = AnsibleDecrypt.decrypt(k, v, auth.manager_ref)
      new_value                = ENCRYPTED_ATTRIBUTES.include?(authentication_attribute) ? ManageIQ::Password.encrypt(decrypted_value) : decrypted_value

      if authentication_attribute
        auth.send("#{authentication_attribute}=", new_value)
      else
        say("Unknown credential field #{k}, ignoring")
      end
    end
    auth.manager_ref = auth.id.to_s
    auth.save!
  end

  def script_path
    @script_path ||= Pathname.new(__dir__).join("data", File.basename(__FILE__, ".rb")).join("standalone_decrypt.py").to_s
  end
end

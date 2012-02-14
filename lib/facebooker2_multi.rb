# Facebooker2Multi
require "mogli"
module Facebooker2Multi

  @oauth2 = true
  @cookie_prefix = 'fbsr_'

  class NotConfigured < Exception; end
  class << self
    attr_accessor :cookie_prefix, :oauth2, :configurations
  end

  def self.api_key(app_config)
    Facebooker2Multi.pull_from_configuration_or_throw_exception(app_config,"api_key")
  end

  def self.secret(app_config)
    Facebooker2Multi.pull_from_configuration_or_throw_exception(app_config,"secret")
  end

  def self.app_id(app_config)
    Facebooker2Multi.pull_from_configuration_or_throw_exception(app_config,"app_id")
  end

  def self.raise_unconfigured_exception(app_config)
    raise NotConfigured.new("No configuration named #{app_config.inspect} provided for Facebooker2Multi. Make sure it is provided in the yaml file and the yaml file is loaded via Facebooker2Multi.load_facebooker_yaml on initialization.")
  end

  # def self.configurations=(hash)
  #   self.configurations = hash
  # end

  def self.load_facebooker_yaml
    config = (YAML.load(ERB.new(File.read(File.join(::Rails.root,"config","facebooker.yml"))).result)[::Rails.env])
    raise NotConfigured.new("Unable to load configuration for #{::Rails.env} from facebooker.yml. Is it set up?") if config.nil?
    self.configurations = config.with_indifferent_access
  end

  def self.cast_to_facebook_id(object)
    if object.kind_of?(Mogli::Profile)
      object.id
    elsif object.respond_to?(:facebook_id)
      object.facebook_id
    else
      object
    end
  end

  def self.pull_from_configuration_or_throw_exception(app_config,field)
    if configurations[app_config] && configurations[app_config][field]
      configurations[app_config][field]
    else
      raise_unconfigured_exception(app_config)
    end
  end
end


require "facebooker2_multi/rails/controller"
require "facebooker2_multi/rails/helpers/facebook_connect"
require "facebooker2_multi/rails/helpers/javascript"
require "facebooker2_multi/rails/helpers/request_forms"
require "facebooker2_multi/rails/helpers/user"
require "facebooker2_multi/rails/helpers"
require "facebooker2_multi/rack/post_canvas"
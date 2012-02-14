# Facebooker2Multi
require "mogli"
module Facebooker2Multi

  @oauth2 = true
  @cookie_prefix = 'fbsr_'

  class NotConfigured < Exception; end
  class << self
    attr_accessor :api_key, :secret, :app_id, :cookie_prefix, :oauth2
  end

  def self.secret
    @secret || raise_unconfigured_exception
  end

  def self.app_id
    @app_id || raise_unconfigured_exception
  end

  def self.raise_unconfigured_exception
    raise NotConfigured.new("No configuration provided for Facebooker2Multi. Either set the app_id and secret or call Facebooker2Multi.load_facebooker_yaml in an initializer")
  end

  def self.configuration=(hash)
    self.api_key = hash[:api_key]
    self.secret = hash[:secret]
    self.app_id = hash[:app_id]
  end

  def self.load_facebooker_yaml
    config = (YAML.load(ERB.new(File.read(File.join(::Rails.root,"config","facebooker.yml"))).result)[::Rails.env])
    raise NotConfigured.new("Unable to load configuration for #{::Rails.env} from facebooker.yml. Is it set up?") if config.nil?
    self.configuration = config.with_indifferent_access
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
end


require "facebooker2_multi/rails/controller"
require "facebooker2_multi/rails/helpers/facebook_connect"
require "facebooker2_multi/rails/helpers/javascript"
require "facebooker2_multi/rails/helpers/request_forms"
require "facebooker2_multi/rails/helpers/user"
require "facebooker2_multi/rails/helpers"
require "facebooker2_multi/rack/post_canvas"
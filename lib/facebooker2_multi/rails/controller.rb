require "digest/md5"
require "hmac-sha2"
module Facebooker2Multi
  module Rails
    module Controller

      def self.included(controller)
        controller.helper Facebooker2Multi::Rails::Helpers
        controller.helper_method :current_facebook_user
        controller.helper_method :current_facebook_client
        controller.helper_method :facebook_params
      end

      def current_facebook_user(app_config)
        if (Facebooker2Multi.oauth2)
          oauth2_fetch_client_and_user(app_config)
        else
          fetch_client_and_user(app_config)
        end
        @_current_facebook_user[app_config]
      end

      def current_facebook_client(app_config)
        if (Facebooker2Multi.oauth2)
          oauth2_fetch_client_and_user(app_config)
        else
          fetch_client_and_user(app_config)
        end
        @_current_facebook_client[app_config]
      end

      # This mimics the getSession logic from the php facebook SDK
      # https://github.com/facebook/php-sdk/blob/master/src/facebook.php#L333
      #
      def fetch_client_and_user(app_config)
        return unless (@_fb_user_fetched.blank? || (@_fb_user_fetched && @_fb_user_fetched[app_config].blank?))
        # Try to authenticate from the signed request first
        sig = fetch_client_and_user_from_signed_request(app_config)
        sig = fetch_client_and_user_from_cookie(app_config) if (@_current_facebook_client.blank? || (@_current_facebook_client && @_current_facebook_client[app_config].blank?)) and !signed_request_from_logged_out_user?(app_config)

        #write the authentication params to a new cookie
        if !(@_current_facebook_client.blank? || (@_current_facebook_client && @_current_facebook_client[app_config].blank?))
          #we may have generated the signature based on the params in @facebook_params, and the expiration here is different

          set_fb_cookie(@_current_facebook_client[app_config].access_token, @_current_facebook_client[app_config].expiration, @_current_facebook_user[app_config].id, sig,app_config)
        else
          # if we do not have a client, delete the cookie
          set_fb_cookie(nil,nil,nil,nil,app_config)
        end

        if @_fb_user_fetched.nil?
          @_fb_user_fetched = {}
        end

        @_fb_user_fetched[app_config] = true
      end

      def fetch_client_and_user_from_cookie(app_config)
        if (hash_data = fb_cookie_hash(app_config)) and
          fb_cookie_signature_correct?(fb_cookie_hash(app_config),Facebooker2Multi.secret(app_config))
          fb_create_user_and_client(hash_data["access_token"],hash_data["expires"],hash_data["uid"],app_config)
          return fb_cookie_hash(app_config)["sig"]
        end
      end

      def fb_create_user_and_client(token,expires,userid,app_config)
        client = Mogli::Client.new(token,expires.to_i)
        user = Mogli::User.new(:id=>userid)
        fb_sign_in_user_and_client(user,client,app_config)
      end

      def fb_sign_in_user_and_client(user,client,app_config)
        user.client = client
        if @_current_facebook_user.nil?
          @_current_facebook_user = {}
        end
        @_current_facebook_user[app_config] = user

        if @_current_facebook_client.nil?
          @_current_facebook_client = {}
        end
        @_current_facebook_client[app_config] = client

        if @_fb_user_fetched.nil?
          @_fb_user_fetched = {}
        end
        @_fb_user_fetched[app_config] = true
      end

      def fb_cookie_hash(app_config)
        return nil unless fb_cookie?(app_config)
        hash={}
        data = fb_cookie(app_config).gsub(/"/,"")
        data.split("&").each do |str|
          parts = str.split("=")
          hash[parts.first] = parts.last
        end
        hash
      end

      def fb_cookie?(app_config)
        !fb_cookie(app_config).blank?
      end

      def fb_cookie(app_config)
        cookies[fb_cookie_name(app_config)]
      end

      def fb_cookie_name(app_config)
        return "#{Facebooker2Multi.cookie_prefix + Facebooker2Multi.app_id(app_config).to_s}"
      end

      # check if the expected signature matches the one from facebook
      def fb_cookie_signature_correct?(hash,secret)
        generate_signature(hash,secret) == hash["sig"]
      end

      # If the signed request is valid but contains no oauth token,
      # the user is either logged out from Facebook or has not authorized the app
      def signed_request_from_logged_out_user?(app_config)
        !facebook_params(app_config).empty? && facebook_params(app_config)[:oauth_token].nil?
      end

      # compute the md5 sig based on access_token,expires,uid, and the app secret
      def generate_signature(hash,secret)
        sorted_keys = hash.keys.reject {|k| k=="sig"}.sort
        test_string = ""
        sorted_keys.each do |key|
          test_string += "#{key}=#{hash[key]}"
        end
        test_string += secret
        sig = Digest::MD5.hexdigest(test_string)
        return sig
      end

      def fb_signed_request_json(encoded)
        chars_to_add = 4-(encoded.size % 4)
        encoded += ("=" * chars_to_add)
        Base64.decode64(encoded)
      end

      def facebook_params(app_config)
        @facebook_param ||= fb_load_facebook_params(app_config)
      end

      def fb_load_facebook_params(app_config)
        return {} if params[:signed_request].blank?
        sig,encoded_json = params[:signed_request].split(".")
        return {} unless fb_signed_request_sig_valid?(sig,encoded_json,app_config)
        ActiveSupport::JSON.decode(fb_signed_request_json(encoded_json)).with_indifferent_access
      end

      def fb_signed_request_sig_valid?(sig,encoded,app_config)
        base64 = Base64.encode64(HMAC::SHA256.digest(Facebooker2Multi.secret(app_config),encoded))
        #now make the url changes that facebook makes
        url_escaped_base64 = base64.gsub(/=*\n?$/,"").tr("+/","-_")
        sig ==  url_escaped_base64
      end

      def fetch_client_and_user_from_signed_request(app_config)
        if facebook_params(app_config)[:oauth_token]
          fb_create_user_and_client(facebook_params(app_config)[:oauth_token],facebook_params(app_config)[:expires],facebook_params(app_config)[:user_id],app_config)

          unless (@_current_facebook_client.blank? || (@_current_facebook_client && @_current_facebook_client[app_config].blank?))
            #compute a signature so we can store it in the cookie
            sig_hash = Hash["uid"=>facebook_params(app_config)[:user_id],"access_token"=>facebook_params(app_config)[:oauth_token],"expires"=>facebook_params(app_config)[:expires]]
            return generate_signature(sig_hash, Facebooker2Multi.secret(app_config))
          end
        end
      end


      # /**
      #   This method was shamelessly stolen from the php facebook SDK:
      #   https://github.com/facebook/php-sdk/blob/master/src/facebook.php
      #
      #    Set a JS Cookie based on the _passed in_ session. It does not use the
      #    currently stored session -- you need to explicitly pass it in.
      #
      #   If a nil access_token is passed in this method will actually delete the fbs_ cookie
      #
      #   */
      def set_fb_cookie(access_token,expires,uid,sig,app_config)

        #default values for the cookie
        value = 'deleted'
        expires = Time.now.utc - 3600 unless expires != nil

        # If the expires value is set to some large value in the future, then the 'offline access' permission has been
        # granted.  In the Facebook JS SDK, this causes a value of 0 to be set for the expires parameter.  This value
        # needs to be correct otherwise the request signing fails, so if the expires parameter retrieved from the graph
        # api is more than a year in the future, then we set expires to 0 to match the JS SDK.
        expires = 0 if expires > Time.now + 1.year

        if access_token
          # Retrieve the existing cookie data
          data = fb_cookie_hash(app_config) || {}
          # Remove the deleted value if this has previously been set, as we don't want to include it as part of the
          # request signing parameters
          data.delete('deleted') if data.key?('deleted')
          # Keep existing cookie data that could have been set by FB JS SDK
          data.merge!('access_token' => access_token, 'uid' => uid, 'sig' => sig, 'expires' => expires.to_i.to_s)
          # Create string to store in cookie
          value = '"'
          data.each do |k,v|
            value += "#{k.to_s}=#{v.to_s}&"
          end
          value.chop!
          value+='"'
        end

        # if an existing cookie is not set, we dont need to delete it
        if (value == 'deleted' && (!fb_cookie?(app_config) || fb_cookie(app_config) == "" ))
          return;
        end

        #My browser doesn't seem to save the cookie if I set expires
        cookies[fb_cookie_name(app_config)] = { :value=>value }#, :expires=>expires}
      end


      # For canvas apps, You need to set the p3p header in order to get IE 6/7 to accept the third-party cookie
      # For details http://www.softwareprojects.com/resources/programming/t-how-to-get-internet-explorer-to-use-cookies-inside-1612.html
      def set_p3p_header_for_third_party_cookies
        response.headers['P3P'] = 'CP="IDC DSP COR ADM DEVi TAIi PSA PSD IVAi IVDi CONi HIS OUR IND CNT"'
      end

      ### Oauth2
      def oauth2_current_facebook_user(app_config)
        oauth2_fetch_client_and_user(app_config)
        @_current_facebook_user[app_config]
      end

      def oauth2_fetch_client_and_user(app_config)
        return unless (@_fb_user_fetched.blank? || (@_fb_user_fetched && @_fb_user_fetched[app_config].blank?))
        sig = oauth2_fetch_client_and_user_from_cookie(app_config) if (@_current_facebook_client.blank? || (@_current_facebook_client && @_current_facebook_client[app_config.blank?]))
        if @_fb_user_fetched.nil?
          @_fb_user_fetched = {}
        end

        @_fb_user_fetched[app_config] = true
      end

      def oauth2_fetch_client_and_user_from_cookie(app_config)
        return unless fb_cookie?(app_config)
        sig,payload = fb_cookie(app_config).split('.')
        return unless fb_signed_request_sig_valid?(sig, payload,app_config)
        data = JSON.parse(base64_url_decode(payload))
        authenticator = Mogli::Authenticator.new(Facebooker2Multi.app_id(app_config), Facebooker2Multi.secret(app_config), nil)
        client = Mogli::Client.create_from_code_and_authenticator(data["code"], authenticator)
        user = Mogli::User.new(:id=>data["user_id"])
        fb_sign_in_user_and_client(user, client,app_config)
      end


      def base64_url_decode(encoded)
        chars_to_add = 4-(encoded.size % 4)
        encoded += ("=" * chars_to_add)
        Base64.decode64(encoded.tr("-_", "+/"))
      end

    end
  end
end

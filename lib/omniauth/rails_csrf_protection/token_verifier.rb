require "active_support/configurable"
require "action_controller"

module OmniAuth
  module RailsCsrfProtection
    # Provides a callable method that verifies Cross-Site Request Forgery
    # protection token. This class includes
    # `ActionController::RequestForgeryProtection` directly and utilizes
    # `verified_request?` method to match the way Rails performs token
    # verification in Rails controllers.
    #
    # If you like to learn more about how Rails generate and verify
    # authenticity token, you can find the source code at
    # https://github.com/rails/rails/blob/v5.2.2/actionpack/lib/action_controller/metal/request_forgery_protection.rb#L217-L240.
    class TokenVerifier
      include ActiveSupport::Configurable
      include ActionController::RequestForgeryProtection

      # `ActionController::RequestForgeryProtection` contains a few
      # configurable options. As we want to make sure that our configuration is
      # the same as what being set in `ActionController::Base`, we should make
      # all out configuration methods to delegate to `ActionController::Base`.
      config.each_key do |configuration_name|
        undef_method configuration_name
        define_method configuration_name do
          ActionController::Base.config[configuration_name]
        end
      end

      def call(env)
        @request = ActionDispatch::Request.new(env)

        unless verified_request?
          protection_method_class.new(self).handle_unverified_request
        end
      end

      attr_reader :request

      private

      delegate :params, :session, :reset_session, to: :request

      def protection_method_class
        ActionController::RequestForgeryProtection::ProtectionMethods.const_get(protection_method.to_s.classify)
      rescue NameError
        ActionController::RequestForgeryProtection::ProtectionMethods::Exception
      end

      def protection_method
        if OmniAuth.config.protect_csrf_with.respond_to? :call
          OmniAuth.config.protect_csrf_with.call request
        else
          OmniAuth.config.protect_csrf_with
        end
      end
    end
  end
end

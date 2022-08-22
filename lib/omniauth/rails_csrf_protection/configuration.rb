module OmniAuth
  module OmniAuthCSRFConfigurationExtension
    attr_accessor :protect_csrf_with

    def self.included(receiver)
      receiver.defaults[:protect_csrf_with] = :exception
      OmniAuth.config.protect_csrf_with ||= :exception
    end
  end
end

OmniAuth::Configuration.include OmniAuth::OmniAuthCSRFConfigurationExtension

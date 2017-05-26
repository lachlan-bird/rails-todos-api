class JsonWebToken 
    # secret key to encode and decode
    HMAC_SECRET = Rails.application.secrets.secret_key_base

    def self.encode(payload, exp = 24.hours.from_now)

        # expire in 24 hours
        payload[:exp] = exp.to_i

        # sign the token with the secret
        JWT.encode(payload, HMAC_SECRET)
    end

    def self.decode(token)

        body = JWT.decode(token, HMAC_SECRET)[0]
        HashWithIndifferentAccess.new body

        # rescue from expired token
        rescue JWT::ExpiredSignature, JWT::VerificationError => e
            raise ExceptionHandler::ExpiredSignature, e.message
    end
end
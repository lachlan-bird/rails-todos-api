class AuthorizeApiRequest
    def initialize(headers = {})
        @headers = headers
    end

    # service entry point
    def call 
        {
            user: user
        }
    end

    private 

    attr_reader :headers

    def user
        # check db
        @user ||= User.find(decoded_auth_token[:user_id]) if decoded_auth_token

        rescue ActiveRecord::RecordNotFound => e
            # raise custom error
            raise(
            ExceptionHandler::InvalidToken,
            ("#{Message.invalid_token} #{e.message}")
            )
    end

    # decode
    def decoded_auth_token
        @decoded_auth_token ||= JsonWebToken.decode(http_auth_header)
    end

    # check whether the token was passed in the request
    def http_auth_header
        if headers['Authorization'].present?
            # Authorization: token
            return headers['Authorization'].split(' ').last
        end

        raise(ExceptionHandler::MissingToken, Message.missing_token)
    end
end
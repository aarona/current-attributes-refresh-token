class ApplicationController < ActionController::API
  include JwtRefreshAccessAuthentication

  rescue_from StandardError, with: :handle_internal_error
  rescue_from ActiveRecord::RecordNotFound, with: :handle_not_found
  rescue_from ActionController::ParameterMissing, with: :handle_parameter_missing

  before_action :authenticate_request

  private

  def render_success(data, meta: {}, status: :ok)
    render json: { data:, meta:, errors: [] }, status:
  end

  def render_error(message, code: nil, status: :bad_request, field: nil)
    error = { message: }
    error[:code] = code if code
    error[:field] = field if field

    render json: { data: nil, meta: {}, errors: [error] }, status:
  end

  def render_validation_errors(model)
    errors = model.errors.map do |error|
      {
        field: error.attribute,
        message: error.message,
        code: 'validation_error'
      }
    end

    render json: { data: nil, meta: {}, errors: }, status: :unprocessable_entity
  end

  def render_not_found(resource_type = 'Resource')
    resource_name = case resource_type
                    when Class
                      resource_type.name
                    when String
                      resource_type
                    else
                      resource_type.to_s
                    end

    render_error("#{resource_name} not found", code: 'not_found', status: :not_found)
  end

  def handle_internal_error(exception)
    Rails.logger.error "Internal Error: #{exception.message}"
    Rails.logger.error exception.backtrace.join("\n")

    render_error('Internal server error', code: 'internal_error', status: :internal_server_error)
  end

  def handle_not_found(exception)
    Rails.logger.error "Not found test: #{exception.inspect}"
    render_not_found
  end

  def handle_parameter_missing(exception)
    Rails.logger.error "Missing Param test: #{exception.inspect}"
    render_error(
      "Required parameter missing: #{exception.param}",
      code: 'parameter_missing',
      status: :bad_request
    )
  end
end

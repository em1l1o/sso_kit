module SsoKit
  module_function

  def check_token(request)
    binding.pry
    request.cookies[:token].blank?
  end
end

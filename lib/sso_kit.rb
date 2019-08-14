# sso client rails edition
class SsoKit
  def initialize(binding)
    @binding = binding
  end

  def verify_token
    incoming_request = eval('request', @binding)
    token = incoming_request.cookies[:token]
    # TODO (zhangjiayuan): 考虑对 raise 的异常进行归类整理
    raise 'cookie 未带有 token' if token.blank?
    raise '验证 token 失败' unless verify(token)
  end

  private

  def verify(token)
    # TODO (zhangjiayuan): use uri config file
    url = "https://xiguacity.cn/server/auth/touch-session"
    data = { token: token }
    response = Http.new(url, 'post', data).run
    result = JSON.parse response.body
    return false if response.code != 200
    # 防止中间人攻击，验证返回的 token 是否与传出的一致
    return false if token != result[:token]
    true
  end
end

module Http
  def initialize(url, method, data)
    uri = URI(url)
    @request = eval("Net::HTTP::#{method.capitalize}").new(uri)
    @request.set_form_data(data)
  end

  def run
    # send request
    use_ssl = @request.uri.scheme == 'https'
    Net::HTTP.start(@request.uri.host, @request.uri.port, use_ssl: use_ssl, read_timeout: 5) do |http|
      http.request @request
    end
  end
end

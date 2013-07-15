spec = Gem::Specification.new do |s|
  s.name = 'facebooker2_multi'
  s.version = '0.0.16'
  s.summary = "Facebook Connect integration library for ruby and rails"
  s.description = "Facebook Connect integration library for ruby and rails"
  s.files = Dir['lib/**/*.rb']
  s.require_path = 'lib'
  s.has_rdoc = false
  s.author = "Mike Mangino"
  s.email = "mmangino@elevatedrails.com"
  s.homepage = "http://developers.facebook.com/docs/api"

  s.add_dependency('mogli', "~> 0.0.29")
  # s.add_dependency('ruby-hmac')

  s.add_development_dependency('rake', '0.9.2.2')
  s.add_development_dependency('rspec', '>= 1.3.1')
  s.add_development_dependency('rspec-rails', '>= 1.3.1')
  s.add_development_dependency('rails', '3.2.13')
end

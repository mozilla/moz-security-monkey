$virtualenv = File.join(node['security_monkey']['homedir'], ".virtualenv")

bash "install_moz_security_monkey" do
  environment ({ 'HOME' => node['security_monkey']['homedir'], 
    'USER' => node['security_monkey']['user'], 
    "SECURITY_MONKEY_SETTINGS" => "#{node['security_monkey']['basedir']}/env-config/config-deploy.py" })
  #user "#{node['security_monkey']['user']}"
  user "root"
  umask "022"
  cwd "/opt/moz-security-monkey/moz-security-monkey/"
  code <<-EOF
  #{$virtualenv}/bin/python setup.py install
  EOF
  action :run
end

link '/opt/secmonkey/moz_manage.py' do
  to '/opt/moz-security-monkey/moz-security-monkey/manage.py'
end

template "#{node['security_monkey']['basedir']}/supervisor/moz_security_monkey.ini" do
  mode "0644"
  source "supervisor/moz_security_monkey.ini.erb"
  variables ({ :virtualenv => $virtualenv })
  notifies :run, "bash[install_supervisor]"
end

bash "install_supervisor" do
  user "root"
  cwd "#{node['security_monkey']['basedir']}/supervisor"
  code <<-EOF
  supervisord -c #{node['security_monkey']['basedir']}/supervisor/moz_security_monkey.ini
  supervisorctl -c #{node['security_monkey']['basedir']}/supervisor/moz_security_monkey.ini
  EOF
  environment 'SECURITY_MONKEY_SETTINGS' => "#{node['security_monkey']['basedir']}/env-config/config-deploy.py"
  action :nothing
end

# TODO : Either replace supervisord with systemd since this is CentOS or create a systemd conf that launches supervisord on boot

template "/etc/cron.d/mozsecuritymonkey" do
  mode "0644"
  source "cron/mozsecuritymonkey"
  variables ({ :virtualenv => $virtualenv })
end

package "certbot"

directory "/usr/share/nginx/html/.well-known"
directory "/usr/share/nginx/html/.well-known/acme-challenge"

execute "create certificate" do
  command "certbot certonly --webroot --webroot-path /usr/share/nginx/html --text --non-interactive --domain #{node[:security_monkey][:target_fqdn]} --email #{node[:security_monkey][:security_team_email]} --agree-tos"
  creates "/etc/letsencrypt/live/#{node[:security_monkey][:target_fqdn]}/fullchain.pem"
end

file "/etc/cron.daily/certbot" do
  # content "/bin/certbot renew --pre-hook "service nginx stop" --post-hook "service nginx start" > /var/log/certbot.log 2>&1\n"
  content "/bin/certbot renew --post-hook "service nginx restart" > /var/log/certbot.log 2>&1\n"
  mode "0755"
end


# TODO : figure out why http nginx doesn't really respond just hangs
# TODO : Setup redirect to https for everything else


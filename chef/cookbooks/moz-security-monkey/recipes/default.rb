$virtualenv = File.join(node['security_monkey']['homedir'], ".virtualenv")

bash "install_moz_security_monkey" do
  environment ({ 'HOME' => node['security_monkey']['homedir'], 
    'USER' => node['security_monkey']['user'], 
    "SECURITY_MONKEY_SETTINGS" => "#{node['security_monkey']['basedir']}/env-config/config-deploy.py" })
  #user "#{node['security_monkey']['user']}"
  user "root"
  umask "022"
  cwd "/root/moz-security-monkey/moz-security-monkey/"
  code <<-EOF
  #{$virtualenv}/bin/python setup.py install
  EOF
  action :run
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
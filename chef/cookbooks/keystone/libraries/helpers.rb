module KeystoneHelper
  def self.service_URL(node, host, port)
    "#{node[:keystone][:api][:protocol]}://#{host}:#{port}"
  end

  def self.versioned_service_URL(node, host, port)
    service_URL(node, host, port) + '/' + node[:keystone][:api][:version] + '/'
  end

  def self.keystone_settings(current_node, cookbook_name)
    keystone_settings = CrowbarConfig.fetch("openstack", "keystone").clone
    keystone_settings['service_user'] = current_node[cookbook_name][:service_user]
    keystone_settings['service_password'] = current_node[cookbook_name][:service_password]

    keystone_settings
  end
end

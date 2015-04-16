#
# Copyright 2011-2013, Dell
# Copyright 2013-2014, SUSE LINUX Products GmbH
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

class KeystoneService < PacemakerServiceObject

  def initialize(thelogger)
    super(thelogger)
    @bc_name = "keystone"
  end
# Turn off multi proposal support till it really works and people ask for it.
  def self.allow_multiple_proposals?
    false
  end

  class << self
    def role_constraints
      {
        "keystone-server" => {
          "unique" => false,
          "count" => 1,
          "exclude_platform" => {
            "suse" => "12.0",
            "windows" => "/.*/"
          },
          "cluster" => true
        }
      }
    end
  end

  def proposal_dependencies(role)
    answer = []
    answer << { "barclamp" => "database", "inst" => role.default_attributes["keystone"]["database_instance"] }
    answer << { "barclamp" => "rabbitmq", "inst" => role.default_attributes["keystone"]["rabbitmq_instance"] }
    if role.default_attributes[@bc_name]["use_gitrepo"]
      answer << { "barclamp" => "git", "inst" => role.default_attributes[@bc_name]["git_instance"] }
    end
    answer
  end

  def create_proposal
    base = super

    nodes = NodeObject.all
    nodes.delete_if { |n| n.nil? or n.admin? }

    base["attributes"][@bc_name]["git_instance"] = find_dep_proposal("git", true)
    base["attributes"][@bc_name]["database_instance"] = find_dep_proposal("database")
    base["attributes"][@bc_name]["rabbitmq_instance"] = find_dep_proposal("rabbitmq")

    if nodes.size >= 1
      controller = nodes.find { |n| n.intended_role == "controller" } || nodes.first
      base["deployment"]["keystone"]["elements"] = {
        "keystone-server" => [ controller[:fqdn] ]
      }
    end


    base["attributes"][@bc_name][:service][:token] = random_password
    base["attributes"][@bc_name][:db][:password] = random_password

    base
  end

  def validate_proposal_after_save proposal
    validate_one_for_role proposal, "keystone-server"

    if proposal["attributes"][@bc_name]["use_gitrepo"]
      validate_dep_proposal_is_active "git", proposal["attributes"][@bc_name]["git_instance"]
    end

    super
  end

  def export_to_deployment_config(role)
    def service_URL(protocol, host, port)
      "#{protocol}://#{host}:#{port}"
    end

    def versioned_service_URL(protocol, host, port, api_version)
      service_URL(protocol, host, port) + '/' + api_version + '/'
    end

    @logger.debug("Keystone export_to_deployment_config: entering")

    attributes = role.default_attributes[@bc_name]
    deployment = role.override_attributes[@bc_name]

    config = DeploymentConfig.new("openstack", @bc_name)

    server_element = deployment["elements"]["keystone-server"].first

    # FIXME: should likely be an attribute
    default_api_version = "v2.0"
    use_ssl = attributes["api"]["protocol"] == "https"

    if server_element.nil?
      admin_host = "127.0.0.1"
      public_host = "127.0.0.1"
    else
      admin_host = OpenstackHelpers.get_host_for_admin_url(server_element)
      public_host = OpenstackHelpers.get_host_for_public_url(server_element, use_ssl)
    end

    config.set({
      "api_version" => default_api_version.sub(/^v/, ""),
      "admin_auth_url" => service_URL(attributes["api"]["protocol"], admin_host, attributes["api"]["admin_port"]),
      "public_auth_url" => versioned_service_URL(attributes["api"]["protocol"], public_host, attributes["api"]["service_port"], default_api_version),
      "internal_auth_url" => versioned_service_URL(attributes["api"]["protocol"], admin_host, attributes["api"]["service_port"], default_api_version),
      "use_ssl" => use_ssl,
      "endpoint_region" => attributes["api"]["region"],
      "insecure" => use_ssl && attributes["ssl"]["insecure"],
      "protocol" => attributes["api"]["protocol"],
      "public_url_host" => public_host,
      "internal_url_host" => admin_host,
      "service_port" => attributes["api"]["service_port"],
      "admin_port" => attributes["api"]["admin_port"],
      "admin_token" => attributes["service"]["token"],
      "admin_tenant" => attributes["admin"]["tenant"],
      "admin_user" => attributes["admin"]["username"],
      "admin_password" => attributes["admin"]["password"],
      "default_tenant" => attributes["default"]["tenant"],
      "default_user" => attributes["default"]["username"],
      "default_password" => attributes["default"]["password"],
      "service_tenant" => attributes["service"]["tenant"]
    })

    config.save

    @logger.debug("Keystone export_to_deployment_config: leaving")
  end

  def apply_role_pre_chef_call(old_role, role, all_nodes)
    @logger.debug("Keystone apply_role_pre_chef_call: entering #{all_nodes.inspect}")

    server_elements, server_nodes, ha_enabled = role_expand_elements(role, "keystone-server")

    vip_networks = ["admin", "public"]

    dirty = false
    dirty = prepare_role_for_ha_with_haproxy(role, ["keystone", "ha", "enabled"], ha_enabled, server_elements, vip_networks)
    role.save if dirty

    unless all_nodes.empty? || server_elements.empty?
      net_svc = NetworkService.new @logger
      # All nodes must have a public IP, even if part of a cluster; otherwise
      # the VIP can't be moved to the nodes
      server_nodes.each do |node|
        net_svc.allocate_ip "default", "public", "host", node
      end

      allocate_virtual_ips_for_any_cluster_in_networks_and_sync_dns(server_elements, vip_networks)
    end

    @logger.debug("Keystone apply_role_pre_chef_call: leaving")
  end

end


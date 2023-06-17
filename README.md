# Vault Secret Engine plugin for Apache Kafka

An experimental Vault plugin to create dynamic Kafka users using SCRAM authentication (default SCRAM-SHA-256). Users are authorized based on Kafka ACLs (configured through the plugin's `/role` HTTP endpoint). The plugin does not rely on any ZooKeeper APIs so this plugin *should* work with KRAFT-enabled clusters. The minimum supported Kafka version is **2.7**

This is mainly for educational purposes. I'm not super convinced that it is a great idea to manage Kafka authentication and authorization dynamically through a secrets-management system like Vault. Kafka clients are generally long-running processes that might not lend themselves well to credential rotation. For a mature production setup, it might be better to create static users and rely on a custom Kafka authorizer plugin for to delegate authorization to other ACL systems like [Keycloak](https://github.com/strimzi/strimzi-kafka-oauth) or [Open Policy Agent](https://github.com/StyraInc/opa-kafka-plugin).

Another option is to lift Kafka ACL management into a declarative configuration layer such as Terraform or Kubernetes. Consider
[Banzai Cloud Kafka Operator](https://banzaicloud.com/docs/supertubes/kafka-operator/) and its Kubernetes CRDs or the  [Kafka Terraform provider](https://registry.terraform.io/providers/Mongey/kafka/latest/docs) and its kafka_acl resource.

In order to use this plugin, you should have a Kafka cluster whose bootstrap-server(s) are reachable from the Vault server with an advertised listener using SCRAM-SHA-256 or SCRAM-SHA-512 authentication. There must be an existing Kafka user authorized to perform indiscriminant `Create` and `Delete` operations on the Kafka ACL `cluster` resource for all hosts in order to configure this plugin.

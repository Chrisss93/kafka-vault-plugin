# Vault Secret Engine plugin for Apache Kafka

An experimental Vault plugin to create dynamic Kafka users using SCRAM authentication (default SCRAM-SHA-256). Users are authorized based on Kafka ACLs (configured through the plugin's `/role` HTTP endpoint). The plugin does not rely on any ZooKeeper APIs so this plugin *should* work with KRAFT-enabled clusters. The minimum supported Kafka version is **2.7**


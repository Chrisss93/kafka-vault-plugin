# Vault Secret Engine plugin for Apache Kafka

An experimental vault plugin for generating dynamic, ephemeral Kafka credentials based on [Kafka Delegation Tokens](https://docs.confluent.io/platform/current/kafka/authentication_sasl/authentication_sasl_delegation.html#kafka-sasl-delegate-auth).  This plugin requires a kafka cluster with an advertised listener configured for SCRAM based SASL authentication (SHA-256 or SHA-512).  In addition, the target kafka cluster must have enabled Delegation Token features (i.e. brokers' server.properties file must have an appropriate entry for the `delegation.token.master.key` key).  The minimum supported Kafka version is **3.3** for Zookeeper-based clusters and **3.6** for KRaft-based clusters.

### Plugin user minimal ACLs

```
ACLs for resource `ResourcePattern(resourceType=CLUSTER, name=kafka-cluster, patternType=LITERAL)`:
 	(principal=User:[the-plugin-user], host=*, operation=DESCRIBE, permissionType=ALLOW)

ACLs for resource `ResourcePattern(resourceType=USER, name=*, patternType=LITERAL)`: 
 	(principal=User:[the-plugin-user], host=*, operation=CREATE_TOKENS, permissionType=ALLOW)
```

## Workflow

To use this plugin, first write to its `/config` endpoint and supply it with the necessary details in order to reach the target kafka cluster.  The SCRAM-based user/password credentials supplied to this endpoint must be empowered to create delegation tokens on behalf of other Kafka users.

The `/token/[user-name]` endpoint may now be written to, which generates a delegation-token with the same privileges as the supplied user-name.  The user-name must already exist on the Kafka cluster.  This delegation token is a leased secret which must be renewed before its TTL elapses.  An end-user of the plugin may take the endpoint's response and use the TokenID and HMAC as the user and password entries respectively for authenticating with a Kafka cluster via a SCRAM mechanism.  This assumes that the client using these credentials follows the rules behind delegation-token authentication defined [here](https://cwiki.apache.org/confluence/display/KAFKA/KIP-48+Delegation+token+support+for+Kafka#KIP48DelegationtokensupportforKafka-SCRAMExtensions) (`,tokenauth=true` must be appended to the client-first message).  This is supported for JVM Kafka clients via JAAS configuration but other clients may need additional work to support delegation token authentication.

## Managing Kafka users

Additionally, the plugin has the ability to manage Kafka users and ACLs directly, if the plugin user and cluster supports it.  This allows the plugin to generate delegation tokens restrained by particular ACLs which do not yet exist on behalf of users who do not yet exist on the cluster. The target kafka cluster must have enabled ACL features (i.e. brokers' server.properties files should have an appropriate entry for the `authorizer.class.name` key).

First, pseudo Kafka ACLs must be created (stored only in Vault) to establish the privileges of the eventual tokens.  These must be writen to the plugin's `/acl` endpoint and resemble Kafka ACLs in all ways *except* that the Principal is omitted and the permission-type is always set to `ALLOW`.

Then, the `/principal/[name]` endpoint may be written to, given a comma-separated list of previously created pseudo Kafka-ACLs in Vault. This creates a SCRAM user in the Kafka cluster and applies the corresponding ACLs to it.  This is NOT the user which should be used by the plugin's end-users (in fact the credentials are never stored in Vault).

Now tokens can be issued against this newly created kafka user as before.  If the `/principal/[name]` is deleted in Vault, it also deletes the SCRAM user as well as its associated ACLs from the Kafka cluster and invalidates all its tokens.  The leases in vault will not be revoked but the secrets will be unusable (until I find a means to perform mass lease revocation within the custom plugin framework).


### Plugin user ACLs for managing Kafka users (not just issuing tokens on pre-existing users)

```
ACLs for resource `ResourcePattern(resourceType=CLUSTER, name=kafka-cluster, patternType=LITERAL)`:
	(principal=User:[the-plugin-user], host=*, operation=DESCRIBE, permissionType=ALLOW)
 	(principal=User:[the-plugin-user], host=*, operation=DESCRIBE_CONFIGS, permissionType=ALLOW)
	(principal=User:[the-plugin-user], host=*, operation=ALTER, permissionType=ALLOW)
	(principal=User:[the-plugin-user], host=*, operation=ALTER_CONFIGS, permissionType=ALLOW)

ACLs for resource `ResourcePattern(resourceType=USER, name=*, patternType=LITERAL)`: 
 	(principal=User:[the-plugin-user], host=*, operation=CREATE_TOKENS, permissionType=ALLOW)
```

## TODO

* Updating/deleting ACLs in Vault affect Kafka ACLs on the cluster

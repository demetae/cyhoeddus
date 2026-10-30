# Build reviews

Oracle CIS audit material, Kubernetes/OpenShift tooling and Kafka review resources.

[Back to repository index](../README.md)

## Contents

| File or folder                                                                                                   | Description                                                                                                                   |
| ---------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| [kafka/kafka_readonly_review.sh](kafka/kafka_readonly_review.sh)                                                 | Kafka network/TLS review script; produces candidate findings for analyst review.                                              |
| [kafka/rocksdbjni-10.1.3.jar](kafka/rocksdbjni-10.1.3.jar)                                                       | Standalone RocksDB JNI library retained alongside the Kafka material.                                                         |
| [kafka/vendor/kafka_2.13-4.3.1](kafka/vendor/kafka_2.13-4.3.1)                                                   | Bundled Kafka distribution, including original LICENSE, NOTICE and third-party licences; repeated parent directories removed. |
| [kubernetes/k8s-openshift.zip](kubernetes/k8s-openshift.zip)                                                     | Archive containing the Kubernetes/OpenShift audit script and its README.                                                      |
| [oracle/12c_SESSIONS_PER_USER_CHECK_CDB_Multitenant.sql](oracle/12c_SESSIONS_PER_USER_CHECK_CDB_Multitenant.sql) | Oracle CIS audit query/procedure material; version is recorded in the filename/content.                                       |
| [oracle/12c_SESSIONS_PER_USER_CHECK_Non-Multitenant.sql](oracle/12c_SESSIONS_PER_USER_CHECK_Non-Multitenant.sql) | Oracle CIS audit query/procedure material; version is recorded in the filename/content.                                       |
| [oracle/oracle_19c_cis_benchmark_audit_queries.txt](oracle/oracle_19c_cis_benchmark_audit_queries.txt)           | Oracle CIS audit query/procedure material; version is recorded in the filename/content.                                       |
| [oracle/oracle_19c_cis_database_audit_runner.sql](oracle/oracle_19c_cis_database_audit_runner.sql)               | Oracle CIS audit query/procedure material; version is recorded in the filename/content.                                       |

## Kafka notes

The review script retains its existing `TESTSSL` default and environment overrides. Its embedded usage text refers to `kafka_readonly_review_v15.sh`; the stored filename is `kafka_readonly_review.sh`. The vendor distribution retains its own internal directory structure.

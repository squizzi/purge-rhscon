// RHSC db cleaner, pulled from steps found in
// https://access.redhat.com/solutions/2944461
//
// Intended for use with rhscon-purge.py for automating
// Red Hat Storage Console reinitialization
// See: https://github.com/squizzi/rhscon-purge for more info
use skyring
db.storage.drop()
db.storage_nodes.drop()
db.storage_clusters.drop()
db.skyring_utilization.drop()
db.cluster_summary.drop()
db.storage_logical_units.drop()
db.tasks.drop()
db.block_devices.drop()
exit

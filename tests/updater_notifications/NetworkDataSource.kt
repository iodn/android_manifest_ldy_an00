// SPDX-License-Identifier: Apache-2.0
package org.lineageos.updater.data.source.network
import org.lineageos.updater.data.Update
data class NetworkUpdate(val update: Update)
fun NetworkUpdate.toUpdate() = update
class UpdatesNetworkDataSource {
    var updates = emptyList<NetworkUpdate>()
    var calls = 0
    fun fetchUpdates(): List<NetworkUpdate> { calls++; return updates }
}

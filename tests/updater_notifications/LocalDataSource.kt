// SPDX-License-Identifier: Apache-2.0
package org.lineageos.updater.data.source.local
import kotlinx.coroutines.flow.flowOf
import org.lineageos.updater.data.Update
class UpdatesLocalDataSource {
    private val rows = linkedMapOf<String, Update>()
    fun getUpdates() = rows.values.toList()
    fun observeUpdates() = flowOf(getUpdates())
    fun removeUpdate(id: String) { rows.remove(id) }
    fun addUpdate(update: Update) { rows[update.downloadId] = update }
}

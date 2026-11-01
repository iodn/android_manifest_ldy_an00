// SPDX-License-Identifier: Apache-2.0
package org.lineageos.updater.util
class NetworkMonitor(var online: Boolean = true) {
    data class State(val isOnline: Boolean)
    val currentNetworkState get() = State(online)
}

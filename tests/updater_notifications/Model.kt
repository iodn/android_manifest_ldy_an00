// SPDX-License-Identifier: Apache-2.0
package org.lineageos.updater.data
import java.io.File
data class Status(val persistentStatus: Int = 0)
data class Update(val downloadId: String, val timestamp: Long,
    val osSdkLevel: Int = 37, val type: String = "UNOFFICIAL",
    val name: String = downloadId, val status: Status = Status(),
    val file: File? = null, val downloadUrl: String? = "https://example.invalid/update.zip") {
    companion object { const val LOCAL_ID = "local" }
}

// SPDX-License-Identifier: Apache-2.0
import kotlinx.coroutines.runBlocking
import org.lineageos.updater.data.*
import org.lineageos.updater.data.source.local.UpdatesLocalDataSource
import org.lineageos.updater.data.source.network.*
import org.lineageos.updater.notifications.NotificationHelper
import org.lineageos.updater.util.NetworkMonitor
import org.lineageos.updater.util.releaseNotesUrl
private class Fixture {
    val network = UpdatesNetworkDataSource()
    val monitor = NetworkMonitor()
    val notifications = NotificationHelper()
    val repository = UpdatesRepository(monitor, notifications, network, UpdatesLocalDataSource())
    fun feed(vararg dates: Long) { network.updates = dates.map { NetworkUpdate(Update("id-$it", it)) } }
}
fun main() = runBlocking {
    val failures = mutableListOf<String>()
    fun expect(name: String, good: Boolean) {
        println("${if (good) "PASS" else "FAIL"}: $name")
        if (!good) failures.add(name)
    }
    val f = Fixture()
    f.feed(200); f.repository.fetchUpdates()
    expect("empty history: first future update notifies", f.notifications.count == 1)
    f.repository.fetchUpdates()
    expect("identical refresh: no duplicate alert", f.notifications.count == 1)
    f.feed(200, 300); f.repository.fetchUpdates()
    expect("later new update: one additional alert", f.notifications.count == 2)
    for ((name, dates) in listOf("empty" to longArrayOf(), "current" to longArrayOf(100), "older" to longArrayOf(99))) {
        val q = Fixture(); q.feed(*dates); q.repository.fetchUpdates()
        expect("$name feed: no notification", q.notifications.count == 0)
    }
    val offline = Fixture(); offline.feed(200); offline.monitor.online = false
    expect("offline: no fetch timestamp", offline.repository.fetchUpdates() == null)
    expect("offline: no network request or alert", offline.network.calls == 0 && offline.notifications.count == 0)
    val base = "https://github.com/iodn/android_manifest_ldy_an00/releases/"
    val tag1 = "lineage-24.0-20261031-UNOFFICIAL-ldy_an00"
    val tag2 = "lineage-24.0-20261130-UNOFFICIAL-ldy_an00"
    for (tag in listOf(tag1, tag2)) {
        expect("release notes select $tag", releaseNotesUrl("${base}download/$tag/$tag-ota.zip") == "${base}tag/$tag")
    }
    for ((name, url) in listOf(
        "null" to null,
        "non-GitHub" to "https://example.invalid/releases/download/$tag1/update.zip",
        "other repository" to "https://github.com/other/project/releases/download/$tag1/update.zip",
        "missing asset" to "${base}download/$tag1/",
        "HTTP" to "http://github.com/iodn/android_manifest_ldy_an00/releases/download/$tag1/update.zip",
        "credentials" to "https://user@github.com/iodn/android_manifest_ldy_an00/releases/download/$tag1/update.zip",
        "query" to "${base}download/$tag1/update.zip?token=value",
        "malformed tag" to "${base}download/lineage-%2Fbad/update.zip",
    )) {
        expect("reject release notes URL: $name", releaseNotesUrl(url) == null)
    }
    check(failures.isEmpty()) { "Notification regression: ${failures.joinToString()}" }
    println("UPDATER_NOTIFICATION_AND_RELEASE_NOTES_TESTS_OK (18 checks; actual production methods)")
}

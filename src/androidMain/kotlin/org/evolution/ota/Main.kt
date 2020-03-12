@file:Suppress("EXPERIMENTAL_UNSIGNED_LITERALS", "EXPERIMENTAL_API_USAGE")

package org.evolution.ota

import platform.posix.*
import com.soywiz.krypto.SHA1
import kotlinx.cinterop.*
import kotlinx.cinterop.nativeHeap.alloc
import platform.linux.*


/* File format:
1: 20 bytes SHA1 of the system partition before
2a. Total number of bytes added (unsigned long, 8 bytes)
2b. Total number of bytes removed (unsigned long, 8 bytes)
3: Null-terminated file path
4: N=(4 bytes patch size)
5: N bytes patch data
6: 20 bytes SHA1 of the patch, including steps 2 and 3
7: repeat steps 2-5 until EOF
 */

/* Method:
Note, the selinux metadata should be the first file to be updated
Note, the updater process should have permission to relabel selinux, and to create or delete any context
1. Create a backup file
2. Create a new mountpoint and mount the real /system to it via a bind mount
3. Pick a file to update
4. Bind mount the old copy of the file over the real path it should go to, so that processes don't get weird mixed versions
5. Delete the old copy of the file from the mountpoint created in 2 (this works because ext4 will create a "shadow" file with a new name, that contains the old data, see https://access.redhat.com/solutions/2316)
6. Create a new file in the mountpoint of step 2. Set the xattrs, stat, etc, but don't worry about selinux - we can use restorecon
6. Repeat steps 3-5
 */

const val TESTING = true

fun calculateSystemDigestAndBackup(systemPath: String, backupFile: CPointer<FILE>): ByteArray {
    println("Verifying... ")
    val currentSystemSHA1 = SHA1()
    memScoped {
        val systemPartition: CPointer<FILE> = fopen(systemPath, "rb")!!
        try {
            require(fseek(systemPartition, 0, SEEK_END) == 0) { "seek to end failed" }
            val fileSize = ftell(systemPartition)
            require(fseek(systemPartition, 0, SEEK_SET) == 0) { "seek to start failed" }
            val chunkCount = fileSize / currentSystemSHA1.chunkSize
            val scratch = allocArray<ByteVar>(currentSystemSHA1.chunkSize)
            var chunkId = 0
            while (true) {
                val chunk = systemPartition.read(currentSystemSHA1.chunkSize, scratch)
                if (chunk.isEmpty())
                    break
                currentSystemSHA1.update(chunk)
                backupFile.write(chunk)
                if (chunkId++.rem(10) == 0)
                    print("\r$chunkId /\t$chunkCount chunks")
            }
            println()
        } finally {
            fclose(systemPartition)
        }
    }
    return currentSystemSHA1.digest()
}

fun getFileName(updateFile: CPointer<FILE>): String = memScoped {
    val path = alloc<CArrayPointerVar<ByteVar>>()
    val n = alloc<size_tVar>()
    val read = getdelim(path.ptr, n.ptr, 0, updateFile)
    require(read in 1 until PATH_MAX) { "read failed ($read)" }
    path.value!!.toKString()
}

fun getSystemMount(systemPath: String): String {
    if (TESTING) return "testSystem"
    val mntFile = setmntent("/proc/mounts", "r")!!
    try {
        while (true) {
            val ent = getmntent(mntFile) ?: break
            if (ent.pointed.mnt_fsname!!.toKString() == systemPath) return ent.pointed.mnt_dir!!.toKString()
        }
    } finally {
        endmntent(mntFile)
    }
    error("system not mounted (searched for $systemPath)")
}

fun getBytesCount(updateFile: CPointer<FILE>): Pair<ULong, ULong> {
    val data = updateFile.read(16)
    return Pair(data.getULongAt(0), data.getULongAt(8))
}

/**
 * If not enough storage is available, throw an error
 * @return whether ptrace is needed
 */
fun verifyStorage(bytesCount: Pair<ULong, ULong>, systemMountPoint: String): Boolean = memScoped {
    val stat = alloc<statvfs>()
    statvfs(systemMountPoint, stat.ptr)
    val freeSpace = stat.f_bfree * stat.f_bavail
    if (bytesCount.first - bytesCount.second >= freeSpace)
        error("Insufficient storage")
    return bytesCount.first >= freeSpace
}

fun prepareMounts(backupFile: CPointer<FILE>, backupFilePath: String, systemBlockDevice: String, systemMountPoint: String, tmpSystemDir: String, tmpBackupDir: String) {
    fseek(backupFile, 0, SEEK_SET)
    require(mount(systemBlockDevice, systemMountPoint, null, MS_REMOUNT.toULong() or MS_PRIVATE.toULong(), null) == 0) { "mounting system r/w failed" }
    require(mount(systemMountPoint, tmpSystemDir, null, MS_BIND.toULong() or MS_REC.toULong(), null) == 0) { "binding system failed" }
    require(mount(backupFilePath, tmpBackupDir, "ext4", MS_PRIVATE.toULong() or MS_RDONLY.toULong(), null) == 0) { "mounting backup failed" }
}

fun easyMove(dest: String, srcFile: Int, off: off_tVar, len: size_t) {
    remove(dest)
    val destFile = open(dest, O_WRONLY)
    while (sendfile(destFile, srcFile, off.ptr, len) == -1L && errno == EINTR) {}
}

fun updateFile(systemMountPoint: String, tmpSystemDir: String, fileName: String, fileSize: Int, fileData: (Int) -> ByteArray, usePtrace: Boolean) {
    val systemPath = pJoin(systemMountPoint, fileName)
    val tmpPath = pJoin(tmpSystemDir, fileName)
    require(mount(systemPath, tmpPath, null, MS_BIND.toULong(), null) == 0) { "bind failed" }
    easyMove(systemPath, tmpPath)
    /*if (usePtrace)
        ptraceMove(systemPath, tmpPath)
    else
    */
    require(access(tmpPath, F_OK) == -1) { "" }
    fopen(tmpPath, "wb")
}

fun updateFile(systemMountPoint: String, tmpSystemDir: String, updateFile: CPointer<FILE>, usePtrace: Boolean) {
    val fileName = getFileName(updateFile)
    val fileSize = updateFile.read(4)
    updateFile(systemMountPoint, tmpSystemDir, fileName, fileSize, { byteArrayOf() }, usePtrace)
}

fun main(vararg args: String) = runWithPerror {
    // TODO ArgParser
    require(args.size == 3) { "usage: updater.kexe /path/to/system/image /path/to/update/file /path/to/backup/file /path/to/tmp/dir" }
    val systemPath = args[0]
    val systemMountPoint = getSystemMount(systemPath)
    println("systemMount = $systemMountPoint")
    val updateFile: CPointer<FILE> = fopen(args[1], "rb")!!
    val magic = updateFile.read(8)
    require(magic.contentEquals("EVOXUPD".encodeToByteArray() + 0.toByte())) { "invalid header: ${magic.contentToString()}" }
    val targetSystemDigest = updateFile.read(20).toUByteArray()
    var backupFile = fopen(args[2], "wb")
    val currentSystemDigest = calculateSystemDigestAndBackup(systemPath, backupFile!!).toUByteArray()
    require(targetSystemDigest.all { it == 0.toUByte() } || currentSystemDigest.contentEquals(targetSystemDigest)) { "Current system (${currentSystemDigest.joinToString("") { it.toString(16) }}) does not match target system (${targetSystemDigest.joinToString("") { it.toString(16) }})" }
    val bytesCount = getBytesCount(updateFile)
    println("bytesCount=$bytesCount")
    val fileName = getFileName(updateFile)
    println("file=$fileName")
    val requiresPtrace = verifyStorage(bytesCount, systemMountPoint)
    val tmpSystemDir = pJoin(args[3], "system")
    val tmpBackupDir = pJoin(args[3], "backup")
    prepareMounts(backupFile, args[2], systemPath, systemMountPoint, tmpSystemDir, tmpBackupDir)
    fclose(backupFile)
    backupFile = null
    while (true) {
        updateFile(systemMountPoint, tmpSystemDir, requiresPtrace)
    }
}

/**
 * Read [n] bytes from the file
 * No chunking or buffering takes place
 * [buffer] must be at least n bytes long, and will be used as scratch. It can be passed to reduce allocations in a loop
 */
fun CPointer<FILE>.read(n: Int, buffer: CArrayPointer<ByteVar>): ByteArray = read(n, this, buffer)
fun CPointer<FILE>.read(n: Int): ByteArray = memScoped { read(n, this@read, allocArray(n)) }

private fun read(n: Int, file: CPointer<FILE>, buffer: CArrayPointer<ByteVar>): ByteArray {
    val size = fread(buffer, 1U, n.toULong(), file)
    if (size == 0UL) {
        require(feof(file) != 0) { "read failed: ${strerror(ferror(file))?.toKString()}" }
        return byteArrayOf()
    }
    return (0 until size.toInt()).map { i -> buffer[i] }.toByteArray()
}

private inline fun <R>runWithPerror(crossinline block: () -> R) {
    try {
        block()
    } catch (e: Throwable) {
        if (errno != 0)
            println("errno = ${strerror(errno)?.toKString()}")
        throw e
    }
}

private fun CPointer<FILE>.write(data: ByteArray): Unit = memScoped { fputs(data.toKString(), this@write) }
private fun CPointer<FILE>.write(data: String): Unit = memScoped { fputs(data, this@write) }

private fun pJoin(vararg paths: String) = paths.map { it.trim('/') }.joinToString("/")
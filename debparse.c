/*
 * Copyright (C) 2025 Colin Ian King
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 */

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <fcntl.h>
#include <errno.h>
#include <libgen.h>
#include <sys/stat.h>

#include <archive.h>
#include <archive_entry.h>

/*
 * Debian header field sizes
 *   https://upload.wikimedia.org/wikipedia/commons/6/67/Deb_File_Structure.svg
 */
#define DEB_HDR_SIGNATURE_SIZE	 (8)
#define DEB_HDR_FILE_ID_SIZE	(16)
#define DEB_HDR_TIMESTAMP_SIZE	(12)
#define DEB_HDR_OWNER_ID_SIZE	 (6)
#define DEB_HDR_GROUP_ID_SIZE	 (6)
#define DEB_HDR_FILE_MODE_SIZE	 (8)
#define DEB_HDR_FILE_SIZE_SIZE	(10)
#define DEB_HDR_END_CHAR_SIZE	 (2)

#define DEB_PACKAGE_VERSION_SIZE (4)

/* Size of chunks to read from tar file */
#define TAR_FILE_DATA_SIZE	(1024)

#define OPT_VERBOSE		(0x01)	/* -v option, verbose error messages */

static int options;	/* optarg options */

/*
 *  Debian archive file signature
 */
typedef struct {
	char signature[DEB_HDR_SIGNATURE_SIZE];
} deb_signature_t;

/*
 *  Debian archive file information;
 */
typedef struct {
	char file_id[DEB_HDR_FILE_ID_SIZE];     /* file identifier */
	char timestamp[DEB_HDR_TIMESTAMP_SIZE]; /* file timestamp */
	char owner_id[DEB_HDR_OWNER_ID_SIZE];   /* file owner ID */
	char group_id[DEB_HDR_GROUP_ID_SIZE];   /* file group ID */
	char file_mode[DEB_HDR_FILE_MODE_SIZE]; /* file mode */
	char file_size[DEB_HDR_FILE_SIZE_SIZE]; /* file size */
	char end_char[DEB_HDR_END_CHAR_SIZE];   /* end marker*/
} deb_section_t;

/*
 *  archive file context for data reading
 */
typedef struct {
	int fd;				/* file descriptor */
	off_t file_size;		/* size of file in bytes */
	char data[TAR_FILE_DATA_SIZE];	/* read buffer */
} tar_file_t;

/*
 *  callback function for examining tar file entries
 */
typedef bool (*tar_callback_func_t)(struct archive *ar, struct archive_entry *entry);

static void pr_error(const char *fmt, ...) __attribute__ ((format (printf, 1, 2)));

/*
 *  pr_error()
 *  	printf like error printing, emits detailed
 *  	error message when using -v flag (helpful for
 *  	debugging malformed packaged), or just
 *  	"malformed package" in default mode as per
 *  	the specification.
 */
static void pr_error(const char *fmt, ...)
{
        va_list ap;

        va_start(ap, fmt);
	if (options & OPT_VERBOSE)
		vfprintf(stderr, fmt, ap);
	else
		fprintf(stderr, "malformed package\n");
        va_end(ap);
}

/*
 *  usage()
 *	show usage of the tool
 */
static void usage(const char *name)
{
	fprintf(stderr, "usage: %s [-h -v] [ debfiles ]\n", name);
}

/*
 *  trim_newline()
 *	trim trailing \n off strings
 */
static void trim_newline(char *str)
{
	char *ptr;

	ptr = strchr(str, '\n');
	if (ptr)
		*ptr = '\0';
}

/*
 *  tar_read()
 *	read up to tf->file_size bytes from tar file, this
 *	is a call-back from  archive_read to get next block
 *	of data from current tar file.
 */
static la_ssize_t tar_read(
	struct archive *ar,
	void *client_data,
	const void **buf)
{
	tar_file_t *tf = (tar_file_t *)client_data;
	ssize_t ret, n;

	(void)ar;	/* not used */

	/* should not happen */
	if (!tf)
		return (la_ssize_t)-1;
	/*
	 *  Read either a full buffer or up to
	 *  the tar file size
	 */
	n = sizeof(tf->data) > tf->file_size ? tf->file_size : sizeof(tf->data);
	*buf = tf->data;

	ret = read(tf->fd, tf->data, n);
	if (ret > 0)
		tf->file_size -= ret;
	return ret;
}

/*
 *  debparse_untar()
 *	uncompress and untar the next tar file
 *	in the debian .deb file.
 */
static int debparse_untar(
	const int fd,			/* deb file fd */
	const off_t file_size,		/* size of tar file in deb file */
	tar_callback_func_t func)	/* per tar entry callback func */
{
	struct archive *ar;
	struct archive_entry *entry;
	tar_file_t tf;

	tf.fd = fd;
	tf.file_size = file_size;

	/*
	 *  Setup reading a tar file from current
	 *  position on the fd. Allow all formats
	 *  so we can decompress a range of compressed
	 *  tarball formats.
	 */
	ar = archive_read_new();
	if (!ar)
		return -1;
	if (archive_read_support_filter_all(ar) != ARCHIVE_OK)
		return -1;
	if (archive_read_support_format_all(ar) != ARCHIVE_OK)
		return -1;
	if (archive_read_open(ar, &tf, NULL, tar_read, NULL) != ARCHIVE_OK)
		return -1;

	/*
	 *  Scan over each tar file entry..
	 */
	while (archive_read_next_header(ar, &entry) == ARCHIVE_OK) {
		/*
		 *  If return from func is true we haven't
		 *  read any data from the file so we need
		 *  to read the file entry to skip over it.
		 */
		if (func(ar, entry))
			archive_read_data_skip(ar);
	}

	if (archive_read_free(ar) != ARCHIVE_OK)
		return -1;
	return 0;
}

/*
 *  debparse_u64
 *	parse a non-null terminated byte field of length
 *	len bytes and return a uint64_t in val. Return
 *	the number of uint64_t values parsed where
 *	0 = failed, 1 = success
 */
static int debparse_u64(const char *field, const size_t len, uint64_t *val)
{
	char buf[len + 1];

	/* Got to copy to buf terminate with eos to be able to sscanf */
	(void)memcpy(buf, field, len);
	buf[len] = '\0';

	return sscanf(buf, "%" SCNu64, val);
}

/*
 *  debparse_section()
 *	parse a debian section
 */
static int debparse_section(
	const int fd,
	const char *filename,
	const char *section_name,
	deb_section_t *section,
	off_t *file_size)
{
	size_t ret;
	uint64_t timestamp, file_size_u64;

	ret = read(fd, section, sizeof(*section));
	if (ret != sizeof(*section)) {
		pr_error("error: file '%s' read failure, got only %zd bytes "
			"of  %zd bytes of deb file %s section data\n",
			filename, ret, sizeof(*section), section_name);
		return -1;
	}

	if (debparse_u64(section->timestamp, sizeof(section->timestamp), &timestamp) != 1) {
		pr_error("error: file '%s' %s section invalid numeric timestamp\n",
			filename, section_name);
		return -1;
	}
	if (debparse_u64(section->file_size, sizeof(section->file_size), &file_size_u64) != 1) {
		pr_error("error: file '%s' %s section invalid numeric file size\n",
			filename, section_name);
		return -1;
	}
	*file_size = (off_t)file_size_u64;
	return 0;
}

/*
 *  debparse_package_section()
 *	parse a Debian package section
 *
 *	Basically a package section is a deb_section_t structure
 *	with a 4 byte file containing the debian package version number
 */
static int debparse_package_section(const int fd, const char *filename)
{
	ssize_t ret;
	char version[DEB_PACKAGE_VERSION_SIZE];
	deb_section_t package;
	off_t file_size;

	if (debparse_section(fd, filename, "package", &package, &file_size) < 0)
		return -1;
	/* Sanity check file size */
	if (file_size != DEB_PACKAGE_VERSION_SIZE) {
		pr_error("error: file '%s' package section invalid numeric file size\n",
			filename);
		return -1;
	}
	/* Sanity check debian pacake file id */
	if (memcmp(package.file_id, "debian-binary   ", sizeof(package.file_id))) {
		pr_error("error: file '%s', package section file id mismatch\n",
			filename);
		return -1;
	}
	/* Read and sanity check version field */
	ret = read(fd, version, sizeof(version));
	if (ret != DEB_PACKAGE_VERSION_SIZE) {
		pr_error("error: file '%s' read failure, got only %zd bytes "
			"of  %zd bytes of deb file package section version\n",
			filename, ret, sizeof(version));
		return -1;
	}
	if (memcmp(version, "2.0\n", sizeof(version))) {
		pr_error("error: file '%s' unsupported file version, expected 2.0\n",
			filename);
		return -1;
	}

	/* as per the specification, emit filename and package version */
	trim_newline(version);
	printf("<%s %s>\n", filename, version);

	return 0;
}

/*
 *  debparse_control_field()
 *	quick and dirty scan of entire control file
 *	for matching field tags.
 */
static char *debparse_control_field(const char *data, const char *field)
{
	char *ptr;

	ptr = strstr(data, field);
	if (!ptr)
		return NULL;
	ptr += strlen(field);
	while (*ptr == ' ')
		ptr++;
	return ptr;
}

/*
 *  debparse_control_entry()
 *	call back handler for each file entry in the
 *	control tar file
 */
static bool debparse_control_entry(struct archive *ar, struct archive_entry *entry)
{
	const char *pathname = archive_entry_pathname(entry);
	char *filename, *data, *pkg_name, *pkg_version, *pkg_arch;
	int64_t filesize;

	/* Sanity check */
	if (!pathname) {
		pr_error("error: missing filename in control tar file\n");
		return true;
	}

	/* get the filename part of the full name */
	filename = basename((char *)pathname);
	if (!filename) {
		pr_error("error: cannot extract basename from control tar file\n");
		return true;
	}

	/* Only process control file */
	if (strcmp(filename, "control"))
		return true;

	/* Sanity check control file size */
	filesize = archive_entry_size(entry);
	if (filesize < 1) {
		pr_error("error: invalid Debian control file size in control tar file\n");
		return true;
	}

	/*
	 *  Next we read the control file into the data
	 *  buffer and scan for specific fields and where
	 *  possible extract the strings following the field tags
	 */
	data = malloc((size_t)filesize);
	if (!data) {
		pr_error("error: failed to allocate %" PRId64 " bytes\n", filesize);
		return true;
	}
	if (archive_read_data(ar, data, filesize) < 0) {
		pr_error("error: cannot read control file in control tar file\n");
		return true;
	}
	pkg_name = debparse_control_field(data, "Package:");
	if (!pkg_name) {
		pr_error("error: cannot find Package field in control tar file\n");
		return true;
	}
	pkg_version = debparse_control_field(data, "Version:");
	if (!pkg_version) {
		pr_error("error: cannot find Version field in control tar file\n");
		return true;
	}
	pkg_arch = debparse_control_field(data, "Architecture:");
	if (!pkg_arch) {
		pr_error("error: cannot find Architecture field in control tar file\n");
		return true;
	}

	/* Now that we all have the strings, we can trim off newline */
	trim_newline(pkg_name);
	trim_newline(pkg_version);
	trim_newline(pkg_arch);

	printf("<%s %s %s>\n", pkg_name, pkg_version, pkg_arch);
	free(data);
	return false;
}

/*
 *  debparse_control_section()
 *	parse a debian package control section
 */
static int debparse_control_section(const int fd, const char *filename)
{
	deb_section_t package;
	off_t file_size;

	if (debparse_section(fd, filename, "control", &package, &file_size) < 0)
		return -1;
	if (debparse_untar(fd, file_size, debparse_control_entry) < 0)
		return -1;
	return 0;
}

/*
 *  debparse_data_entry()
 *	callback handler for each file entry in the data section
 *	tar file.
 */
static bool debparse_data_entry(struct archive *ar, struct archive_entry *entry)
{
	const mode_t mode = archive_entry_mode(entry);
	const mode_t mask = S_IXUSR | S_IXGRP | S_IXOTH;

	(void)ar;	/* unused */

	if (S_ISREG(mode) && (mode & mask)) {
		const char *filename = archive_entry_pathname(entry);

		/* skip over leading . in paths leading with ./ */
		if (!strncmp(filename, "./", 2))
			filename++;

		/* and print the executable file name */
		printf("<%s>\n", filename);
	}

	return false;
}

/*
 *  debparse_data_section()
 *	parse a debian package data section
 */
static int debparse_data_section(const int fd, const char *filename)
{
	deb_section_t package;
	off_t file_size;

	if (debparse_section(fd, filename, "data", &package, &file_size) < 0)
		return -1;
	if (debparse_untar(fd, file_size, debparse_data_entry) < 0)
		return -1;
	return 0;
}

/*
 *  debparse()
 *	parse the given debian .deb file
 *	The .deb files have a small signature followed
 *	by 3 file sections: package control and data.
 *	These 3 file sections have a common section
 *	as represented by deb_section_t followed by
 *	a variable sized data portion as described
 *	as follows:
 *
 *	Package: The data portion is a 4 byte debian
 *	version field, currently "2.0\n"
 *
 *	Control: The data portion is a compressed tar
 *	file containing the debian control files
 *
 *	Data:    The data portion is a compressed tar
 *	file containing the package binaries, docs,
 *	manuals, configuration and associated data
 *	that is to be installed.
 */
static int debparse(const char *filename)
{
	int fd;
	deb_signature_t sig;

	ssize_t ret;
	int rc;

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		pr_error("error: file '%s' open failure, errno=%d (%s)\n",
			filename, errno, strerror(errno));
		return -1;
	}

	/* Read the Debian signature */
	ret = read(fd, &sig, sizeof(sig));
	if (ret != sizeof(sig)) {
		pr_error("error: file '%s' read failure, got only %zd bytes "
			"of  %zd bytes of deb package signature\n",
			filename, ret, sizeof(sig));
		(void)close(fd);
		return -1;
	}
	/* Check if signature is valid */
	if (memcmp(sig.signature, "!<arch>\n", sizeof(sig.signature))) {
		pr_error("error: file '%s' debian signature mismatch\n",
			filename);
		(void)close(fd);
		return -1;
	}

	/* Parse the Debian package section */
	rc = debparse_package_section(fd, filename);
	if (rc != EXIT_SUCCESS) {
		(void)close(fd);
		return rc;
	}
	/* Parse the Debian control section */
	rc = debparse_control_section(fd, filename);
	if (rc != EXIT_SUCCESS) {
		(void)close(fd);
		return rc;
	}
	/* Parse the Debian data section */
	rc = debparse_data_section(fd, filename);
	if (rc != EXIT_SUCCESS) {
		(void)close(fd);
		return rc;
	}

	(void)close(fd);
	return 0;
}

int main(int argc, char **argv)
{
	int opt;

	options = 0;

	while ((opt = getopt(argc, argv, "hv")) != -1) {
		switch (opt) {
		case 'h':
		default:
			usage(argv[0]);
			return EXIT_FAILURE;
		case 'v':
			options |= OPT_VERBOSE;
			break;
		}
	}

	if (optind == argc) {
		fprintf(stderr, "please specify deb packages\n");
		usage(argv[0]);
		return EXIT_FAILURE;
	}

	/* parse each debian .deb file */
	while (optind < argc) {
		if (debparse(argv[optind++]) < 0)
			return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

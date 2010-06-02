/*
 * oifw-extract.c
 *
 * Extract data from openinkpot firmware update files.
 *
 * Copyright (c) 2010 Alexey Zautsev  <alexey.zaytsev@gmail.com>
 *
 * Permission is granted to distribute under the therms of the
 * GNU Generic Public License version 2.
 */


/* XXX We don't handle endianess convertion yet */

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <ctype.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <zlib.h>
#include "list.h"

static void usage(const char *prg)
{
	printf("Usage: %s <options> <file>\n", prg);
	printf("Options:\n");
	printf("\t-c\t\tCheck is the file is an OpenInkpot firmware update\n");
	printf("\t-l\t\tList properties\n");
	printf("\t-b\t\tList data blocks\n");
	printf("\t-B<block>\tWork with this block.\n");
	printf("\t-s<property\tRequest a given proerty.\n");
	printf("\t-x\t\tExtract a data block to stdout. Checks the block crc if present.\n");
}

#define OIFW_MAGIC "OIFW"

/*
 *	4 bytes 	magic string 0x4f 0x49 0x46 0x57
 *	4 bytes 	size of file header (from start of file to end of blocks list) 
 */

struct fw_update_head {
	char magic[4];
	uint32_t header_size;
} __attribute__((packed));


/*
 *	4 bytes 	size of property name
 *	4 bytes 	size of property
 *	N bytes 	property name (ASCII string)
 *	N bytes 	property value 
 */
struct prop {
	uint32_t name_size;
	uint32_t value_size;
	char data[];
} __attribute__((packed));

/*
 *	4 bytes 	size of block name
 *	8 bytes 	block offset from the start of file (required to be 4-bytes alinged)
 *	8 bytes 	block size
 *	N bytes 	block name
 *	M bytes 	List of block-specific properties (see above for the format of the properties list) 
 */
struct block {
	uint32_t name_size;
	uint64_t offset;
	uint64_t size;
	char data[];
} __attribute__((packed));


/* We store the parsed data in lists */
struct node {
	struct list_head head;
	struct block *block;
	struct prop *prop;
};

/**
 * container_of - cast a member of a structure out to the containing structure
 * @ptr:	the pointer to the member.
 * @type:	the type of the container struct this is embedded in.
 * @member:	the name of the member within the struct.
 *
 */
#define container_of(ptr, type, member) ({			\
	const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
	(type *)( (char *)__mptr - offsetof(type,member) );})


static int oifw_check_magic(const char *map)
{
	struct fw_update_head *head = (struct fw_update_head *) map;

	return !!strncmp(head->magic, OIFW_MAGIC, 4);
}

static int oifw_parse(const char *map,
		int (*property_func) (struct prop *prop, void *data),
		void *property_data,
		int (*block_func) (struct block *block, void *data),
		void *block_data,
		int (*block_property_func) (struct block *block, struct prop *prop, void *data),
		void *block_property_data)

{
	struct fw_update_head *head = (struct fw_update_head *) map;
	const char *p;
	int ret;

	if (oifw_check_magic(map)) {
		fprintf(stderr, "Broken Openinkpot update file\n");
		return 1;
	}

	p = map + sizeof(struct fw_update_head);
	/* Parse the properties */
	while (p < map + head->header_size) {
		struct prop *prop = (struct prop *) p;

		p +=  sizeof(prop);

		if (prop->name_size == 0)
			break; /* Empty record - end */

		p += (prop->name_size + prop->value_size);
		if (property_func) {
			ret = property_func(prop, property_data);
			if (ret) return ret;
		}
	}

	/* Parse the block list */
	while (p < map + head->header_size) {
		struct block *block = (struct block *) p;

		p += sizeof(struct block);
		if (block->name_size == 0)
			break; /* Empty record - end */

		p += block->name_size;

		if (block_func) {
			ret = block_func(block, block_data);
			if (ret) return ret;
		}

		/* Parse the block properties */
		while (p < map + head->header_size) {
			struct prop *prop = (struct prop *) p;

			p +=  sizeof(struct prop);

			if (prop->name_size == 0)
				break; /* Empty record - end */

			p += (prop->name_size + prop->value_size);
			if (block_property_func) {
				ret = block_property_func(block, prop, block_property_data);
				if (ret) return ret;
			}
		}
	}

	return 0;
}

static int validate_name(const char *name) {

	while(*name) {
		if (!isgraph(*name))
			return 1;
		name++;
	}

	return 0;
}

static int node_accumulate(struct block *block, struct prop *prop, void *data) {
	struct list_head *head = (struct list_head *) data;
	struct node *node;

	if (block && validate_name(block->data)) {
		fprintf(stderr, "Invalid block name: %s\n", block->data);
		return 1;
	}

	if (prop && validate_name(prop->data)) {
		fprintf(stderr, "Invalid property name: %s\n", block->data);
		return 1;
	}

	node = malloc(sizeof(struct node));
	INIT_LIST_HEAD(&node->head);
	node->block = block;
	node->prop = prop;

	list_add_tail(&node->head, head);

	return 0;
}

static int prop_accumulate(struct prop *prop, void *data) {
	return node_accumulate(NULL, prop, data);
}

static int block_accumulate(struct block *block, void *data) {
	return node_accumulate(block, NULL, data);
}

static int block_prop_accumulate(struct block *block, struct prop *prop, void *data) {
	return node_accumulate(block, prop, data);
}

static int oifw_list_properties(const char *map)
{
	struct list_head head;
	struct list_head *tmp;
	int ret;
	INIT_LIST_HEAD(&head);

	ret = oifw_parse(map,
			prop_accumulate, &head,
			NULL, NULL,
			NULL, NULL);
	if (ret) {
		fprintf(stderr, "An error occured while parsing the update file\n");
		return ret;
	}

	list_for_each(tmp, &head) {
		struct node *node = container_of(tmp, struct node, head);
		printf("%s ", node->prop->data);
	}

	printf("\n");

	return 0;

}

static int oifw_list_blocks(const char *map)
{
	struct list_head head;
	struct list_head *tmp;
	int ret;
	INIT_LIST_HEAD(&head);

	ret = oifw_parse(map,
			NULL, NULL,
			block_accumulate, &head,
			NULL, NULL);
	if (ret) {
		fprintf(stderr, "An error occured while parsing the update file\n");
		return ret;
	}

	list_for_each(tmp, &head) {
		struct node *node = container_of(tmp, struct node, head);
		printf("%ld %ld %s\n", node->block->offset,  node->block->size, node->block->data);
	}

	return 0;

}

static int oifw_list_block_properties(const char *map, const char *block)
{
	struct list_head head;
	struct list_head *tmp;
	int ret;
	INIT_LIST_HEAD(&head);

	ret = oifw_parse(map,
			NULL, NULL,
			NULL, NULL,
			block_prop_accumulate, &head);
	if (ret) {
		fprintf(stderr, "An error occured while parsing the update file\n");
		return ret;
	}

	list_for_each(tmp, &head) {
		struct node *node = container_of(tmp, struct node, head);
		if (!strcmp(node->block->data, block))
			printf("%s ", node->prop->data);
	}

	printf("\n");

	return 0;

}

static int write_out(const char *ptr, ssize_t left, int fd)
{
	ssize_t ret;
	while (left) {
		ret = write(fd, ptr, left);
		if (ret == -1) {
			perror("Failed to write the block data to the output");
			return 1;
		}

		left -= ret;
		ptr += ret;
	}

	return 0;
}

static int extract_block(const char *map, struct block *block, int fd)
{
	return write_out(map + block->offset, block->size, fd);
}

static int extract_property(struct prop *prop, int fd)
{
	return write_out(prop->data+prop->name_size, prop->value_size, fd);
}

static int oifw_get_property(const char *map, const char *block, const char *property)
{
	struct list_head prop_head, block_prop_head;
	struct list_head *tmp;
	int ret;
	INIT_LIST_HEAD(&prop_head);
	INIT_LIST_HEAD(&block_prop_head);

	ret = oifw_parse(map,
			prop_accumulate, &prop_head,
			NULL, NULL,
			block_prop_accumulate, &block_prop_head);
	if (ret) {
		fprintf(stderr, "An error occured while parsing the update file\n");
		return ret;
	}

	if (block) {
		list_for_each(tmp, &block_prop_head) {
			struct node *node = container_of(tmp, struct node, head);
			if (!strcmp(node->block->data, block))
				if (!strcmp(node->prop->data, property))
					return extract_property(node->prop, STDOUT_FILENO);
		}
	} else {
		list_for_each(tmp, &prop_head) {
			struct node *node = container_of(tmp, struct node, head);
			if (!strcmp(node->prop->data, property))
				return extract_property(node->prop, STDOUT_FILENO);
		}
	}

	return 0;
}

static int check_block(const char *map, struct block *block, const char *crc_str)
{
	uint32_t crc = atoi(crc_str);
	uint32_t calculated;

	calculated = crc32(0UL, (const unsigned char *)map + block->offset, block->size);

	if (crc != calculated) {
		fprintf(stderr, "CRC check failed for block '%s': 0x%x, should be 0x%x\n",
				block->data, calculated, crc);
		return 1;
	}

	return 0;
}



static int oifw_extract_block(const char *map, const char *block)
{
	struct list_head block_head, block_prop_head;
	struct list_head *tmp;
	int ret;
	INIT_LIST_HEAD(&block_head);
	INIT_LIST_HEAD(&block_prop_head);

	ret = oifw_parse(map,
			NULL, NULL,
			block_accumulate, &block_head,
			block_prop_accumulate, &block_prop_head);
	if (ret) {
		fprintf(stderr, "An error occured while parsing the update file\n");
		return ret;
	}

	list_for_each(tmp, &block_prop_head) {
		struct node *node = container_of(tmp, struct node, head);
		if (!strcmp(node->block->data, block)) {
			if (!strcmp(node->prop->data, "crc32")) {
				if (check_block(map, node->block, node->prop->data + node->prop->name_size)) {
					fprintf(stderr, "CRC check failed\n");
					return 1;
				} else {
					return extract_block(map, node->block, STDOUT_FILENO);
				}
			}
		}
	}

	/* No crc32 property found for this block, extract without checking.*/
	list_for_each(tmp, &block_head) {
		struct node *node = container_of(tmp, struct node, head);
		if (!strcmp(node->block->data, block))
			return extract_block(map, node->block, STDOUT_FILENO);
	}

	fprintf(stderr, "Block not found: %s\n", block);
	return 1;
}

int main(int argc, char *argv[])
{
	int opt;

	int flag_c = 0;
	int flag_l = 0;
	int flag_b = 0;
	int flag_B = 0;
	int flag_x = 0;
	int flag_s = 0;
	char *block;
	char *property;

	int fd;
	const char *map;
	struct stat sb;

	if (argc < 3) {
		usage(argv[0]);
		exit(1);
	}

	while ((opt = getopt(argc, argv, "clbB:s:x")) != -1) {
		switch (opt) {
			case 'c':
				flag_c = 1;
				break;
			case 'l':
				flag_l = 1;
				break;
			case 'b':
				flag_b = 1;
				break;
			case 'B':
				flag_B = 1;
				block = optarg; 
				break;
			case 's':
				flag_s = 1;
				property = optarg; 
				break;
			case 'x':
				flag_x = 1;
				break;
			default:
				usage(argv[0]);
				exit(1);
		}
	}

	fd = open(argv[optind], O_RDONLY);
	if (!fd) {
		perror("Can't open the input file");
		exit(1);
	}
	if (fstat(fd, &sb) == -1) {
		perror("Can't stat the input file");
		exit(1);
	}

	map = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (map == MAP_FAILED) {
		perror("Can't map the inpit file");
		exit(1);
	}

	if (flag_c) {
		printf("%s is %san Openinkpot firmware update file\n", argv[optind], oifw_check_magic(map)?"not ":"");
	}

	if (flag_l) {
		if (flag_B) {
			oifw_list_block_properties(map, block);
		} else {
			oifw_list_properties(map);
		}
	}

	if (flag_b) {
		oifw_list_blocks(map);
	}

	if (flag_s) {
		if (flag_B) {
			oifw_get_property(map, block, property);
		} else {
			oifw_get_property(map, NULL, property);
		}
	}

	if (flag_x) {
		if (!flag_B) {
			fprintf(stderr, "Pelease specify the block name\n");
			exit(1);
		}
		oifw_extract_block(map, block);
	}

	return 0;
}


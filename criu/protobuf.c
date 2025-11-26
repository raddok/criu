#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <ctype.h>

#include <google/protobuf-c/protobuf-c.h>

#include "image.h"
#include "servicefd.h"
#include "common/compiler.h"
#include "log.h"
#include "rst-malloc.h"
#include "string.h"
#include "sockets.h"
#include "cr_options.h"
#include "bfd.h"
#include "protobuf.h"
#include "util.h"
#include "common/xmalloc.h"
#include "imgset.h"

#define image_name(img, buf) __image_name(img, buf, sizeof(buf))
static char *__image_name(struct cr_img *img, char *image_path, size_t image_path_size)
{
	int fd = img->_x.fd;

	if (lazy_image(img))
		return img->path;
	else if (empty_image(img))
		return "(empty-image)";
	else if (fd >= 0 && read_fd_link(fd, image_path, image_path_size) > 0)
		return image_path;

	return NULL;
}

/*
 * Reads PB record (header + packed object) from file @fd and unpack
 * it with @unpack procedure to the pointer @pobj
 *
 *  1 on success
 * -1 on error (or EOF met and @eof set to false)
 *  0 on EOF and @eof set to true
 *
 * Don't forget to free memory granted to unpacked object in calling code if needed
 */

int do_pb_read_one(struct cr_img *img, void **pobj, int type, bool eof)
{
	char img_name_buf[PATH_MAX];
	u8 local[PB_PKOBJ_LOCAL_SIZE];
	void *buf = (void *)&local;
	u32 size;
	int ret;

	if (!cr_pb_descs[type].pb_desc) {
		pr_err("Wrong object requested %d on %s\n", type, image_name(img, img_name_buf));
		return -1;
	}

	*pobj = NULL;

	if (unlikely(empty_image(img)))
		ret = 0;
	else
		ret = bread(&img->_x, &size, sizeof(size));
	if (ret == 0) {
		if (eof) {
			return 0;
		} else {
			pr_err("Unexpected EOF on %s\n", image_name(img, img_name_buf));
			return -1;
		}
	} else if (ret < sizeof(size)) {
		pr_perror("Read %d bytes while %d expected on %s", ret, (int)sizeof(size),
			  image_name(img, img_name_buf));
		return -1;
	}

	if (size > sizeof(local)) {
		ret = -1;
		buf = xmalloc(size);
		if (!buf)
			goto err;
	}

	ret = bread(&img->_x, buf, size);
	if (ret < 0) {
		pr_perror("Can't read %d bytes from file %s", size, image_name(img, img_name_buf));
		goto err;
	} else if (ret != size) {
		pr_perror("Read %d bytes while %d expected from %s", ret, size, image_name(img, img_name_buf));
		ret = -1;
		goto err;
	}

	*pobj = cr_pb_descs[type].unpack(NULL, size, buf);
	if (!*pobj) {
		ret = -1;
		pr_err("Failed unpacking object %p from %s\n", pobj, image_name(img, img_name_buf));
		goto err;
	}

	ret = 1;
err:
	if (buf != (void *)&local)
		xfree(buf);

	return ret;
}

int check_read_index(struct im_img *img, u32 size)
{
	struct img_entry *ime;
	ime = im_imgset_hash[img->type];
	while (ime != NULL) {
		if (ime->id == img->id) {
			int padding = 8 - (img->offset + sizeof(size) + size) % 8;
			if (padding == 8)
				padding = 0;
			ime->offset += sizeof(size) + size + padding;
			ime->size -= sizeof(size) + size + padding;
			pr_info("ime offset now is %ld, size now is %ld\n", ime->offset, ime->size);
			if (ime->size < 0) {
				pr_err("Image size is negative\n");
				return -1;
			}
			if (ime->size == 0) {
				struct im_img_desc *imh;
				pr_info("This entriy of image type %d id %lu have been read\n", img->type, img->id);
				if (ime->next_offset) {
					imh = base_ptr + ime->next_offset;
					ime->offset = ime->next_offset + sizeof(struct im_img_desc);
					ime->size = imh->size;
					ime->next_offset = imh->next_desc;
					pr_info("switching chunk: next is at offset %ld, size %ld, next_offset %ld\n", (void *)imh - base_ptr, imh->size, imh->next_desc);
				}
			}
			img->offset = ime->offset;
			img->size = ime->size;
			break;
		}
		ime = ime->next_entry;
	}
	return 0;
}

int do_pb_read_one_im(struct im_img *img, void **pobj, int type)
{
	u8 local[PB_PKOBJ_LOCAL_SIZE];
	void *buf = (void *)&local;
	u32 size;
	int ret;

	if (!cr_pb_descs[type].pb_desc) {
		pr_err("Wrong object requested %d\n", type);
		return -1;
	}
	if (img->size == 0) {
		pr_info("Image size is 0\n");
		return 0;
	}
	memcpy(&size, base_ptr + img->offset, sizeof(size));
	pr_info("read size is %u, offset is %lu\n", size, img->offset);
	if (size > PB_PKOBJ_LOCAL_SIZE) {
		buf = xmalloc(size);
		if (!buf) {
			ret = -1;
			goto err;
		}
	}
	memcpy(buf, base_ptr + img->offset + sizeof(size), size);

	if (check_read_index(img, size)) {
		ret = -1;
		goto err;
	}
	*pobj = cr_pb_descs[type].unpack(NULL, size, buf);
	if (!*pobj) {
		ret = -1;
		pr_err("Failed unpacking object %p\n", pobj);
		goto err;
	}
	ret = 1;
err:
	if (buf != (void *)&local)
		xfree(buf);

	return ret;
}

int do_pb_read_one_generic(void *img, void **pobj, int type, bool eof)
{
	if (opts.image_type == IMAGE_TYPE_CR) {
		pr_info("Reading PB object type %d from CR image %p\n", type, img);
		return do_pb_read_one((struct cr_img *)img, pobj, type, eof);
	} else if (opts.image_type == IMAGE_TYPE_IM) {
		pr_info("Reading PB object type %d from IM image %p\n", type, img);
		return do_pb_read_one_im((struct im_img *)img, pobj, type);
	} else {
		pr_err("Unknown image type %d\n", opts.image_type);
		return -1;
	}
}

/*
 * Writes PB record (header + packed object pointed by @obj)
 * to file @fd, using @getpksize to get packed size and @pack
 * to implement packing
 *
 *  0 on success
 * -1 on error
 */
int pb_write_one_cr(struct cr_img *img, void *obj, int type)
{
	u8 local[PB_PKOBJ_LOCAL_SIZE];
	void *buf = (void *)&local;
	u32 size, packed;
	int ret = -1;
	struct iovec iov[2];

	if (!cr_pb_descs[type].pb_desc) {
		pr_err("Wrong object requested %d\n", type);
		return -1;
	}

	if (lazy_image(img) && open_image_lazy(img))
		return -1;

	size = cr_pb_descs[type].getpksize(obj);
	if (size > (u32)sizeof(local)) {
		buf = xmalloc(size);
		if (!buf)
			goto err;
	}

	packed = cr_pb_descs[type].pack(obj, buf);
	if (packed != size) {
		pr_err("Failed packing PB object %p\n", obj);
		goto err;
	}

	iov[0].iov_base = &size;
	iov[0].iov_len = sizeof(size);
	iov[1].iov_base = buf;
	iov[1].iov_len = size;

	ret = bwritev(&img->_x, iov, 2);
	if (ret != size + sizeof(size)) {
		pr_perror("Can't write %d bytes", (int)(size + sizeof(size)));
		goto err;
	}

	ret = 0;
err:
	if (buf != (void *)&local)
		xfree(buf);
	return ret;
}

void im_write_header(int type, unsigned long id)
{
	struct img_entry *ime;
	struct im_img_desc *imh;
	int flag = 0;
	if (!current_im_desc || type != current_im_desc->type) {
		imh = data_head;
		imh->type = type;
		imh->id = id;
		imh->size = 0;
		imh->next_desc = 0;
		im_img_checkpoint->img_nr += 1;
		pr_info("Creating header at offset %ld\n", data_head - base_ptr);
		pr_info("img_nr now is %d\n", im_img_checkpoint->img_nr);
		current_im_desc = imh;
		im_img_checkpoint->total_size += sizeof(struct im_img_desc);
		ime = im_imgset_hash[type];
		if (ime == NULL) {
			ime = xmalloc(sizeof(struct img_entry));
			ime->id = id;
			ime->offset = data_head - base_ptr;
			ime->size = 0;
			ime->next_offset = 0;
			ime->next_entry = NULL;
			im_imgset_hash[type] = ime;
			data_head += sizeof(struct im_img_desc);
			return;
		}
		if (ime->id == id)
			flag = 1;
		while (ime->next_entry != NULL) {
			if (ime->id == id) {
				flag = 1;
				break;
			}
			ime = ime->next_entry;
		}
		if (!flag) {
			pr_info("No exsist header with the same id, img %d updating entry\n", type);
			ime->next_entry = xmalloc(sizeof(struct img_entry));
			ime = ime->next_entry;
			ime->id = id;
			ime->offset = data_head - base_ptr;
			ime->size = 0;
			ime->next_offset = 0;
			ime->next_entry = NULL;
			im_imgset_hash[type] = ime;
		} else {
			pr_info("Found exsist header with the same id, updating previous header at %ld\n", ime->offset);
			imh = base_ptr + ime->offset;
			imh->next_desc = data_head - base_ptr;
			ime->offset = data_head - base_ptr;
		}
		data_head += sizeof(struct im_img_desc);
	}
}

int pb_write_one_im(struct im_img *img, void *obj, int type)
{
	u8 local[PB_PKOBJ_LOCAL_SIZE];
	void *buf = (void *)&local;
	u32 size, packed;
	int ret = -1;
	void *p_data_head;

	if (!cr_pb_descs[type].pb_desc) {
		pr_err("Wrong object requested %d\n", type);
		return -1;
	}
	size = cr_pb_descs[type].getpksize(obj);
	if (size > (u32)sizeof(local)) {
		buf = xmalloc(size);
		if (!buf)
			goto err;
	}
	packed = cr_pb_descs[type].pack(obj, buf);
	if (packed != size) {
		pr_err("Failed packing PB object %p\n", obj);
		goto err;
	}

	im_write_header(img->type, img->id);
	p_data_head = data_head;

	memcpy(data_head, &size, sizeof(size));
	data_head += sizeof(size);
	memcpy(data_head, buf, size);
	data_head += size;
	current_im_desc->size += sizeof(size) + size;
	if ((data_head - base_ptr) % 8 != 0) {
		int padding = 8 - ((data_head - base_ptr) % 8);
		pr_info("Need padding size %d\n", padding);
		data_head += padding;
		current_im_desc->size += padding;
	}

	im_img_checkpoint->total_size += data_head - p_data_head;
	pr_info("Total size now is %ld, image size is %ld\n", im_img_checkpoint->total_size, current_im_desc->size);
	ret = 0;
err:
	if (buf != (void *)&local)
		xfree(buf);
	return ret;
}

int pb_write_one_generic(void *img, void *obj, int type)
{
	char img_name_buf[PATH_MAX];
	if (opts.image_type == IMAGE_TYPE_CR) {
		pr_info("Writing PB object type %d to CR image %s\n", type, image_name((struct cr_img *)img, img_name_buf));
		return pb_write_one_cr((struct cr_img *)img, obj, type);
	} else if (opts.image_type == IMAGE_TYPE_IM) {
		pr_info("Writing PB object type %d to IM image %d\n", type, ((struct im_img *)(img))->type);
		return pb_write_one_im((struct im_img *)img, obj, type);
	} else {
		pr_err("Unknown image type %d\n", opts.image_type);
		return -1;
	}
}

int collect_entry(ProtobufCMessage *msg, struct collect_image_info *cinfo)
{
	void *obj;
	void *(*o_alloc)(size_t size) = malloc;
	void (*o_free)(void *ptr) = free;

	if (cinfo->flags & COLLECT_SHARED) {
		o_alloc = shmalloc;
		o_free = shfree_last;
	}

	if (cinfo->priv_size) {
		obj = o_alloc(cinfo->priv_size);
		if (!obj)
			return -1;
	} else
		obj = NULL;

	cinfo->flags |= COLLECT_HAPPENED;
	if (cinfo->collect(obj, msg, NULL) < 0) {
		o_free(obj);
		cr_pb_descs[cinfo->pb_type].free(msg, NULL);
		return -1;
	}

	if (!cinfo->priv_size && !(cinfo->flags & COLLECT_NOFREE))
		cr_pb_descs[cinfo->pb_type].free(msg, NULL);

	return 0;
}

int collect_image(struct collect_image_info *cinfo)
{
	int ret;
	void *img;
	void *(*o_alloc)(size_t size) = malloc;
	void (*o_free)(void *ptr) = free;

	pr_info("Collecting %d/%d (flags %x)\n", cinfo->fd_type, cinfo->pb_type, cinfo->flags);

	img = open_image(cinfo->fd_type, O_RSTR);
	if (!img)
		return -1;

	if (cinfo->flags & COLLECT_SHARED) {
		o_alloc = shmalloc;
		o_free = shfree_last;
	}

	while (1) {
		void *obj;
		ProtobufCMessage *msg;

		if (cinfo->priv_size) {
			ret = -1;
			obj = o_alloc(cinfo->priv_size);
			if (!obj)
				break;
		} else
			obj = NULL;

		ret = pb_read_one_eof(img, &msg, cinfo->pb_type);
		if (ret <= 0) {
			o_free(obj);
			break;
		}

		cinfo->flags |= COLLECT_HAPPENED;
		ret = cinfo->collect(obj, msg, img);
		if (ret < 0) {
			o_free(obj);
			cr_pb_descs[cinfo->pb_type].free(msg, NULL);
			break;
		}

		if (!cinfo->priv_size && !(cinfo->flags & COLLECT_NOFREE))
			cr_pb_descs[cinfo->pb_type].free(msg, NULL);
	}

	close_image_generic(img);
	pr_debug(" `- ... done\n");
	return ret;
}

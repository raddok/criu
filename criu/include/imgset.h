#ifndef __CR_IMGSET_H__
#define __CR_IMGSET_H__

#include "image-desc.h"
#include "log.h"
#include "common/bug.h"
#include "image.h"

struct cr_imgset {
	int fd_off;
	int fd_nr;
	struct cr_img **_imgs;
};

static inline struct cr_img *img_from_set(const struct cr_imgset *imgset, int type)
{
	int idx;

	idx = type - imgset->fd_off;
	BUG_ON(idx > imgset->fd_nr);

	return imgset->_imgs[idx];
}

struct im_imgset {
	int img_off;
	int img_nr;
	struct im_img **_imgs;
};

static inline struct im_img *im_img_from_set(const struct im_imgset *imgset, int type)
{
	int idx;

	idx = type - imgset->img_off;
	BUG_ON(idx > imgset->img_nr);

	return imgset->_imgs[idx];
}

struct im_img_header {
	unsigned long magic;
	unsigned long total_size;
	int img_nr;
};

extern struct cr_imgset *glob_imgset;

extern struct im_img_header *im_img_checkpoint;

extern int im_imgset_hash[CR_FD_MAX];


extern struct cr_fd_desc_tmpl imgset_template[CR_FD_MAX];

extern struct cr_imgset *cr_task_imgset_open(int pid, int mode);
extern struct im_imgset *im_task_imgset_open(int pid, int mode);
extern struct cr_imgset *cr_imgset_open_range(int pid, int from, int to, unsigned long flags);
extern struct im_imgset *im_imgset_open_range(int pid, int from, int to, unsigned long flags);
#define cr_imgset_open(pid, type, flags) cr_imgset_open_range(pid, _CR_FD_##type##_FROM, _CR_FD_##type##_TO, flags)
#define im_imgset_open(pid, type, flags) im_imgset_open_range(pid, _CR_FD_##type##_FROM, _CR_FD_##type##_TO, flags)
extern struct cr_imgset *cr_glob_imgset_open(int mode);

extern void close_cr_imgset(struct cr_imgset **cr_imgset);
extern void init_im_pointer(void);

#endif /* __CR_IMGSET_H__ */

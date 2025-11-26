#ifndef __CR_IMGSET_H__
#define __CR_IMGSET_H__

#include "image-desc.h"
#include "log.h"
#include "common/bug.h"
#include "image.h"

struct imgset {
	void (*_close_imgset)(struct imgset **self);
	void *(*img_from_set)(const struct imgset *self, int type);
	int offset;
	int nr;
};

struct cr_imgset {
	struct imgset base;
	struct cr_img **_imgs;
};

struct im_imgset {
	struct imgset base;
	struct im_img **_imgs;
};

static inline void *im_img_from_set(const struct imgset *imgset, int type)
{
	int idx;

	idx = type - imgset->offset;
	BUG_ON(idx > imgset->nr);

	return ((struct im_imgset *)(imgset))->_imgs[idx];
}

static inline void *cr_img_from_set(const struct imgset *imgset, int type)
{
	int idx;

	idx = type - imgset->offset;
	BUG_ON(idx > imgset->nr);

	return ((struct cr_imgset *)(imgset))->_imgs[idx];
}
struct im_img_header {
	unsigned long magic;
	unsigned long total_size;
	int img_nr;
};

extern struct imgset *glob_imgset;

extern struct im_img_header *im_img_checkpoint;
extern int daxfd;
extern struct img_entry *im_imgset_hash[CR_FD_MAX];

extern struct cr_fd_desc_tmpl imgset_template[CR_FD_MAX];

extern struct cr_imgset *cr_task_imgset_open(int pid, int mode);
extern struct im_imgset *im_task_imgset_open(int pid, int mode);
extern struct cr_imgset *cr_imgset_open_range(int pid, int from, int to, unsigned long flags);
extern struct im_imgset *im_imgset_open_range(int pid, int from, int to, unsigned long flags);
#define cr_imgset_open(pid, type, flags) cr_imgset_open_range(pid, _CR_FD_##type##_FROM, _CR_FD_##type##_TO, flags)
#define im_imgset_open(pid, type, flags) im_imgset_open_range(pid, _CR_FD_##type##_FROM, _CR_FD_##type##_TO, flags)
extern struct cr_imgset *cr_glob_imgset_open(int mode);
extern struct im_imgset *im_glob_imgset_open(int mode);

extern void close_cr_imgset(struct imgset **cr_imgset);
extern void close_im_imgset(struct imgset **im_imgset);
#define close_imgset(imgset) (*imgset)->_close_imgset(imgset)
extern void init_im_pointer(void);
extern void init_imgset_hash(void);
#define img_from_set(__imgset, __type) ((__imgset)->img_from_set(__imgset, __type))

#endif /* __CR_IMGSET_H__ */

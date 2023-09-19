/*
 * various utility functions for use within FFmpeg
 * Copyright (c) 2000, 2001, 2002 Fabrice Bellard
 *
 * This file is part of FFmpeg.
 *
 * FFmpeg is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * FFmpeg is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with FFmpeg; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <stdint.h>

#include "config.h"

#include "libavutil/avstring.h"
#include "libavutil/bprint.h"
#include "libavutil/internal.h"
#include "libavutil/thread.h"
#include "libavutil/time.h"

#include "libavcodec/internal.h"

#include "avformat.h"
#include "avio_internal.h"
#include "internal.h"
#if CONFIG_NETWORK
#include "network.h"
#endif

static AVMutex avformat_mutex = AV_MUTEX_INITIALIZER;

/**
 * @file
 * various utility functions for use within FFmpeg
 */

int ff_lock_avformat(void)
{
    return ff_mutex_lock(&avformat_mutex) ? -1 : 0;
}

int ff_unlock_avformat(void)
{
    return ff_mutex_unlock(&avformat_mutex) ? -1 : 0;
}

/* an arbitrarily chosen "sane" max packet size -- 50M */
#define SANE_CHUNK_SIZE (50000000)

/* Read the data in sane-sized chunks and append to pkt.
 * Return the number of bytes read or an error. */
static int append_packet_chunked(AVIOContext *s, AVPacket *pkt, int size)
{
    int orig_size      = pkt->size;
    int ret;

    do {
        int prev_size = pkt->size;
        int read_size;

        /* When the caller requests a lot of data, limit it to the amount
         * left in file or SANE_CHUNK_SIZE when it is not known. */
        read_size = size;
        if (read_size > SANE_CHUNK_SIZE/10) {
            read_size = ffio_limit(s, read_size);
            // If filesize/maxsize is unknown, limit to SANE_CHUNK_SIZE
            if (ffiocontext(s)->maxsize < 0)
                read_size = FFMIN(read_size, SANE_CHUNK_SIZE);
        }

        ret = av_grow_packet(pkt, read_size);
        if (ret < 0)
            break;

        ret = avio_read(s, pkt->data + prev_size, read_size);
        if (ret != read_size) {
            av_shrink_packet(pkt, prev_size + FFMAX(ret, 0));
            break;
        }

        size -= read_size;
    } while (size > 0);
    if (size > 0)
        pkt->flags |= AV_PKT_FLAG_CORRUPT;

    if (!pkt->size)
        av_packet_unref(pkt);
    return pkt->size > orig_size ? pkt->size - orig_size : ret;
}

int av_get_packet(AVIOContext *s, AVPacket *pkt, int size)
{
#if FF_API_INIT_PACKET
FF_DISABLE_DEPRECATION_WARNINGS
    av_init_packet(pkt);
    pkt->data = NULL;
    pkt->size = 0;
FF_ENABLE_DEPRECATION_WARNINGS
#else
    av_packet_unref(pkt);
#endif
    pkt->pos  = avio_tell(s);

    return append_packet_chunked(s, pkt, size);
}

int av_append_packet(AVIOContext *s, AVPacket *pkt, int size)
{
    if (!pkt->size)
        return av_get_packet(s, pkt, size);
    return append_packet_chunked(s, pkt, size);
}

int av_filename_number_test(const char *filename)
{
    char buf[1024];
    return filename &&
           (av_get_frame_filename(buf, sizeof(buf), filename, 1) >= 0);
}

/**********************************************************/

unsigned int ff_codec_get_tag(const AVCodecTag *tags, enum AVCodecID id)
{
    while (tags->id != AV_CODEC_ID_NONE) {
        if (tags->id == id)
            return tags->tag;
        tags++;
    }
    return 0;
}

enum AVCodecID ff_codec_get_id(const AVCodecTag *tags, unsigned int tag)
{
    for (int i = 0; tags[i].id != AV_CODEC_ID_NONE; i++)
        if (tag == tags[i].tag)
            return tags[i].id;
    for (int i = 0; tags[i].id != AV_CODEC_ID_NONE; i++)
        if (ff_toupper4(tag) == ff_toupper4(tags[i].tag))
            return tags[i].id;
    return AV_CODEC_ID_NONE;
}

enum AVCodecID ff_get_pcm_codec_id(int bps, int flt, int be, int sflags)
{
    if (bps <= 0 || bps > 64)
        return AV_CODEC_ID_NONE;

    if (flt) {
        switch (bps) {
        case 32:
            return be ? AV_CODEC_ID_PCM_F32BE : AV_CODEC_ID_PCM_F32LE;
        case 64:
            return be ? AV_CODEC_ID_PCM_F64BE : AV_CODEC_ID_PCM_F64LE;
        default:
            return AV_CODEC_ID_NONE;
        }
    } else {
        bps  += 7;
        bps >>= 3;
        if (sflags & (1 << (bps - 1))) {
            switch (bps) {
            case 1:
                return AV_CODEC_ID_PCM_S8;
            case 2:
                return be ? AV_CODEC_ID_PCM_S16BE : AV_CODEC_ID_PCM_S16LE;
            case 3:
                return be ? AV_CODEC_ID_PCM_S24BE : AV_CODEC_ID_PCM_S24LE;
            case 4:
                return be ? AV_CODEC_ID_PCM_S32BE : AV_CODEC_ID_PCM_S32LE;
            case 8:
                return be ? AV_CODEC_ID_PCM_S64BE : AV_CODEC_ID_PCM_S64LE;
            default:
                return AV_CODEC_ID_NONE;
            }
        } else {
            switch (bps) {
            case 1:
                return AV_CODEC_ID_PCM_U8;
            case 2:
                return be ? AV_CODEC_ID_PCM_U16BE : AV_CODEC_ID_PCM_U16LE;
            case 3:
                return be ? AV_CODEC_ID_PCM_U24BE : AV_CODEC_ID_PCM_U24LE;
            case 4:
                return be ? AV_CODEC_ID_PCM_U32BE : AV_CODEC_ID_PCM_U32LE;
            default:
                return AV_CODEC_ID_NONE;
            }
        }
    }
}

unsigned int av_codec_get_tag(const AVCodecTag *const *tags, enum AVCodecID id)
{
    unsigned int tag;
    if (!av_codec_get_tag2(tags, id, &tag))
        return 0;
    return tag;
}

int av_codec_get_tag2(const AVCodecTag * const *tags, enum AVCodecID id,
                      unsigned int *tag)
{
    for (int i = 0; tags && tags[i]; i++) {
        const AVCodecTag *codec_tags = tags[i];
        while (codec_tags->id != AV_CODEC_ID_NONE) {
            if (codec_tags->id == id) {
                *tag = codec_tags->tag;
                return 1;
            }
            codec_tags++;
        }
    }
    return 0;
}

enum AVCodecID av_codec_get_id(const AVCodecTag *const *tags, unsigned int tag)
{
    for (int i = 0; tags && tags[i]; i++) {
        enum AVCodecID id = ff_codec_get_id(tags[i], tag);
        if (id != AV_CODEC_ID_NONE)
            return id;
    }
    return AV_CODEC_ID_NONE;
}

int ff_alloc_extradata(AVCodecParameters *par, int size)
{
    av_freep(&par->extradata);
    par->extradata_size = 0;

    if (size < 0 || size >= INT32_MAX - AV_INPUT_BUFFER_PADDING_SIZE)
        return AVERROR(EINVAL);

    par->extradata = av_malloc(size + AV_INPUT_BUFFER_PADDING_SIZE);
    if (!par->extradata)
        return AVERROR(ENOMEM);

    memset(par->extradata + size, 0, AV_INPUT_BUFFER_PADDING_SIZE);
    par->extradata_size = size;

    return 0;
}

/*******************************************************/

uint64_t ff_ntp_time(void)
{
    return (av_gettime() / 1000) * 1000 + NTP_OFFSET_US;
}

uint64_t ff_get_formatted_ntp_time(uint64_t ntp_time_us)
{
    uint64_t ntp_ts, frac_part, sec;
    uint32_t usec;

    //current ntp time in seconds and micro seconds
    sec = ntp_time_us / 1000000;
    usec = ntp_time_us % 1000000;

    //encoding in ntp timestamp format
    frac_part = usec * 0xFFFFFFFFULL;
    frac_part /= 1000000;

    if (sec > 0xFFFFFFFFULL)
        av_log(NULL, AV_LOG_WARNING, "NTP time format roll over detected\n");

    ntp_ts = sec << 32;
    ntp_ts |= frac_part;

    return ntp_ts;
}

uint64_t ff_parse_ntp_time(uint64_t ntp_ts)
{
    uint64_t sec = ntp_ts >> 32;
    uint64_t frac_part = ntp_ts & 0xFFFFFFFFULL;
    uint64_t usec = (frac_part * 1000000) / 0xFFFFFFFFULL;

    return (sec * 1000000) + usec;
}

int av_get_frame_filename2(char *buf, int buf_size, const char *path, int number, int flags)
{
    const char *p;
    char *q, buf1[20], c;
    int nd, len, percentd_found;

    q = buf;
    p = path;
    percentd_found = 0;
    for (;;) {
        c = *p++;
        if (c == '\0')
            break;
        if (c == '%') {
            do {
                nd = 0;
                while (av_isdigit(*p)) {
                    if (nd >= INT_MAX / 10 - 255)
                        goto fail;
                    nd = nd * 10 + *p++ - '0';
                }
                c = *p++;
            } while (av_isdigit(c));

            switch (c) {
            case '%':
                goto addchar;
            case 'd':
                if (!(flags & AV_FRAME_FILENAME_FLAGS_MULTIPLE) && percentd_found)
                    goto fail;
                percentd_found = 1;
                if (number < 0)
                    nd += 1;
                snprintf(buf1, sizeof(buf1), "%0*d", nd, number);
                len = strlen(buf1);
                if ((q - buf + len) > buf_size - 1)
                    goto fail;
                memcpy(q, buf1, len);
                q += len;
                break;
            default:
                goto fail;
            }
        } else {
addchar:
            if ((q - buf) < buf_size - 1)
                *q++ = c;
        }
    }
    if (!percentd_found)
        goto fail;
    *q = '\0';
    return 0;
fail:
    *q = '\0';
    return -1;
}

int av_get_frame_filename(char *buf, int buf_size, const char *path, int number)
{
    return av_get_frame_filename2(buf, buf_size, path, number, 0);
}

void av_url_split(char *proto, int proto_size,
                  char *authorization, int authorization_size,
                  char *hostname, int hostname_size,
                  int *port_ptr, char *path, int path_size, const char *url)
{
    const char *p, *ls, *at, *at2, *col, *brk;

    if (port_ptr)
        *port_ptr = -1;
    if (proto_size > 0)
        proto[0] = 0;
    if (authorization_size > 0)
        authorization[0] = 0;
    if (hostname_size > 0)
        hostname[0] = 0;
    if (path_size > 0)
        path[0] = 0;

    /* parse protocol */
    if ((p = strchr(url, ':'))) {
        av_strlcpy(proto, url, FFMIN(proto_size, p + 1 - url));
        p++; /* skip ':' */
        if (*p == '/')
            p++;
        if (*p == '/')
            p++;
    } else {
        /* no protocol means plain filename */
        av_strlcpy(path, url, path_size);
        return;
    }

    /* separate path from hostname */
    ls = p + strcspn(p, "/?#");
    av_strlcpy(path, ls, path_size);

    /* the rest is hostname, use that to parse auth/port */
    if (ls != p) {
        /* authorization (user[:pass]@hostname) */
        at2 = p;
        while ((at = strchr(p, '@')) && at < ls) {
            av_strlcpy(authorization, at2,
                       FFMIN(authorization_size, at + 1 - at2));
            p = at + 1; /* skip '@' */
        }

        if (*p == '[' && (brk = strchr(p, ']')) && brk < ls) {
            /* [host]:port */
            av_strlcpy(hostname, p + 1,
                       FFMIN(hostname_size, brk - p));
            if (brk[1] == ':' && port_ptr)
                *port_ptr = atoi(brk + 2);
        } else if ((col = strchr(p, ':')) && col < ls) {
            av_strlcpy(hostname, p,
                       FFMIN(col + 1 - p, hostname_size));
            if (port_ptr)
                *port_ptr = atoi(col + 1);
        } else
            av_strlcpy(hostname, p,
                       FFMIN(ls + 1 - p, hostname_size));
    }
}

int ff_mkdir_p(const char *path)
{
    int ret = 0;
    char *temp = av_strdup(path);
    char *pos = temp;
    char tmp_ch = '\0';

    if (!path || !temp) {
        return -1;
    }

    if (!av_strncasecmp(temp, "/", 1) || !av_strncasecmp(temp, "\\", 1)) {
        pos++;
    } else if (!av_strncasecmp(temp, "./", 2) || !av_strncasecmp(temp, ".\\", 2)) {
        pos += 2;
    }

    for ( ; *pos != '\0'; ++pos) {
        if (*pos == '/' || *pos == '\\') {
            tmp_ch = *pos;
            *pos = '\0';
            ret = mkdir(temp, 0755);
            *pos = tmp_ch;
        }
    }

    if ((*(pos - 1) != '/') && (*(pos - 1) != '\\')) {
        ret = mkdir(temp, 0755);
    }

    av_free(temp);
    return ret;
}

char *ff_data_to_hex(char *buff, const uint8_t *src, int s, int lowercase)
{
    static const char hex_table_uc[16] = { '0', '1', '2', '3',
                                           '4', '5', '6', '7',
                                           '8', '9', 'A', 'B',
                                           'C', 'D', 'E', 'F' };
    static const char hex_table_lc[16] = { '0', '1', '2', '3',
                                           '4', '5', '6', '7',
                                           '8', '9', 'a', 'b',
                                           'c', 'd', 'e', 'f' };
    const char *hex_table = lowercase ? hex_table_lc : hex_table_uc;

    for (int i = 0; i < s; i++) {
        buff[i * 2]     = hex_table[src[i] >> 4];
        buff[i * 2 + 1] = hex_table[src[i] & 0xF];
    }
    buff[2 * s] = '\0';

    return buff;
}

int ff_hex_to_data(uint8_t *data, const char *p)
{
    int c, len, v;

    len = 0;
    v   = 1;
    for (;;) {
        p += strspn(p, SPACE_CHARS);
        if (*p == '\0')
            break;
        c = av_toupper((unsigned char) *p++);
        if (c >= '0' && c <= '9')
            c = c - '0';
        else if (c >= 'A' && c <= 'F')
            c = c - 'A' + 10;
        else
            break;
        v = (v << 4) | c;
        if (v & 0x100) {
            if (data)
                data[len] = v;
            len++;
            v = 1;
        }
    }
    return len;
}

void ff_parse_key_value(const char *str, ff_parse_key_val_cb callback_get_buf,
                        void *context)
{
    const char *ptr = str;

    /* Parse key=value pairs. */
    for (;;) {
        const char *key;
        char *dest = NULL, *dest_end;
        int key_len, dest_len = 0;

        /* Skip whitespace and potential commas. */
        while (*ptr && (av_isspace(*ptr) || *ptr == ','))
            ptr++;
        if (!*ptr)
            break;

        key = ptr;

        if (!(ptr = strchr(key, '=')))
            break;
        ptr++;
        key_len = ptr - key;

        callback_get_buf(context, key, key_len, &dest, &dest_len);
        dest_end = dest ? dest + dest_len - 1 : NULL;

        if (*ptr == '\"') {
            ptr++;
            while (*ptr && *ptr != '\"') {
                if (*ptr == '\\') {
                    if (!ptr[1])
                        break;
                    if (dest && dest < dest_end)
                        *dest++ = ptr[1];
                    ptr += 2;
                } else {
                    if (dest && dest < dest_end)
                        *dest++ = *ptr;
                    ptr++;
                }
            }
            if (*ptr == '\"')
                ptr++;
        } else {
            for (; *ptr && !(av_isspace(*ptr) || *ptr == ','); ptr++)
                if (dest && dest < dest_end)
                    *dest++ = *ptr;
        }
        if (dest)
            *dest = 0;
    }
}

int avformat_network_init(void)
{
#if CONFIG_NETWORK
    int ret;
    if ((ret = ff_network_init()) < 0)
        return ret;
    if ((ret = ff_tls_init()) < 0)
        return ret;
#endif
    return 0;
}

int avformat_network_deinit(void)
{
#if CONFIG_NETWORK
    ff_network_close();
    ff_tls_deinit();
#endif
    return 0;
}

int ff_is_http_proto(const char *filename) {
    const char *proto = avio_find_protocol_name(filename);
    return proto ? (!av_strcasecmp(proto, "http") || !av_strcasecmp(proto, "https")) : 0;
}

int ff_bprint_to_codecpar_extradata(AVCodecParameters *par, struct AVBPrint *buf)
{
    int ret;
    char *str;

    ret = av_bprint_finalize(buf, &str);
    if (ret < 0)
        return ret;
    if (!av_bprint_is_complete(buf)) {
        av_free(str);
        return AVERROR(ENOMEM);
    }

    par->extradata = str;
    /* Note: the string is NUL terminated (so extradata can be read as a
     * string), but the ending character is not accounted in the size (in
     * binary formats you are likely not supposed to mux that character). When
     * extradata is copied, it is also padded with AV_INPUT_BUFFER_PADDING_SIZE
     * zeros. */
    par->extradata_size = buf->len;
    return 0;
}


#if CONFIG_IJK

/* ijkplayer private usage */

#include "libavutil/opt.h"
#include "libavcodec/h264_ps.h"
#include "libavcodec/hevc_ps.h"
#include "libavcodec/hevc_sei.h"
#include "libavcodec/mpeg4audio.h"

#define IJK_MAX_PROBE_COUNT 40
#define IJK_PROBE_MAX_CTX_COUNT 5

#define IJK_STREAM_INFO_UNKNOWN     -1
#define IJK_STREAM_INFO_NOT_SUPPORT -2

#define FF_MAX_CODEC_WIDTH    32768
#define FF_MAX_CODEC_HEIGHT   32768
#define FF_MAX_CODEC_SAMPLERATE   96000

extern int ff_h264_decode_extradata(const uint8_t *data, int size, H264ParamSets *ps,
                                    int *is_avc, int *nal_length_size,
                                    int err_recognition, void *logctx);
extern int ff_hevc_decode_extradata(const uint8_t *data, int size, HEVCParamSets *ps,
                                    HEVCSEI *sei, int *is_nalff, int *nal_length_size,
                                    int err_recognition, int apply_defdispwin, void *logctx);

extern int av_try_read_frame(AVFormatContext *s, int *nb_packets, int64_t *ts, int block);

extern int avformat_add_coded_side_data(AVStream *st, AVCodecContext *avctx);

extern int av_try_find_stream_info(AVFormatContext *ic, AVDictionary **options);

extern void av_update_stream_timings(AVFormatContext *ic);

static
AVCodecContext * create_video_decoder_from_codecpar (AVCodecParameters * codecpar) {
    int ret = 0;
    const AVCodec * codec;
    int is_avc=0;
    int nal_length_size=0;
    int i;
    AVCodecContext * avctx = NULL;

    if (!codecpar || !codecpar->extradata || !codecpar->extradata_size)
        return NULL;

    //Init Video Stream
    if ((codec = avcodec_find_decoder(codecpar->codec_id)) == NULL)
        return NULL;

    if ((avctx = avcodec_alloc_context3(codec)) == NULL)
        return NULL;

    avctx->extradata = av_mallocz(codecpar->extradata_size + AV_INPUT_BUFFER_PADDING_SIZE);
    if (!avctx->extradata) {
        avcodec_free_context(&avctx);
        return NULL;
    }
    avctx->extradata_size = codecpar->extradata_size;
    memcpy(avctx->extradata, codecpar->extradata, avctx->extradata_size);

    //sizeof(HEVCDecoderConfigurationRecord) > sizeof(AVCDecoderConfigurationRecord) >= 7 bytes
    if (avctx->extradata_size < 7) {
        av_log(NULL, AV_LOG_ERROR, "Wrong video extradata length\n");
        avcodec_free_context(&avctx);
        return NULL;
    }

    if (codecpar->codec_id == AV_CODEC_ID_H264) {
        H264ParamSets ps;
        memset(&ps, 0, sizeof(H264ParamSets));
        const PPS *pps = NULL;
        const SPS *sps = NULL;
        if ((ret = ff_h264_decode_extradata(avctx->extradata, avctx->extradata_size, &ps,
                                            &is_avc, &nal_length_size,
                                            0, avctx)) < 0)
            return NULL;
        for (i = 0; i < MAX_PPS_COUNT; i++) {
            if (ps.pps_list[i]) {
                pps = (const PPS*)ps.pps_list[i]->data;
                break;
            }
        }

        if (pps)
            if (ps.sps_list[pps->sps_id])
                sps = (const SPS*)ps.sps_list[pps->sps_id]->data;

        if (pps && sps) {
            avctx->width  = sps->mb_width  * 16 - (sps->crop_right + sps->crop_left);
            avctx->height = sps->mb_height * 16 - (sps->crop_top   + sps->crop_bottom);
            avctx->profile = sps->profile_idc;
            avctx->level   = sps->level_idc;
            avctx->sample_aspect_ratio = sps->vui.sar;
        } else{
            ff_h264_ps_uninit(&ps);
            avcodec_free_context(&avctx);
            return NULL;
        }

        // if nuit_field_based_flag set denote field rate, otherwise denote frame rate
        // Note: x264 always set nuit_field_based_flag but old x264( < 44U) has double framerate bug
        // if (nuit_field_based_flag) {
        //    framerate = time_scale / num_units_in_tick / 2;
        // } else {
        //    framerate = time_scale / num_units_in_tick;
        // }
        // or framerate = time_scale / num_units_in_tick / ticks_per_frame

        // avg_frame_duration = 1 / framerate
        // but frame_duration = (1 + repeat_pict) * num_units_in_tick / time_scale
        // or frame_duration = (1 + repeat_pict) / ticks_per_frame  / framerate
        // Note: h264 internal always set ticks_per_frame to 2, repeat_pict should start at 1 when progressive , >= 2 when interlace

        if (sps->timing_info_present_flag) {
            avctx->time_base = (AVRational){1, sps->time_scale};
            avctx->ticks_per_frame = 2;
            av_reduce(&avctx->framerate.num, &avctx->framerate.den, sps->time_scale,
                      sps->num_units_in_tick * avctx->ticks_per_frame, INT_MAX);
        } else {
            av_log(NULL, AV_LOG_ERROR, "timing_info_present_flag not set , use default timing\n");
        }
        ff_h264_ps_uninit(&ps);
    } else if (codecpar->codec_id == AV_CODEC_ID_H265) {
        HEVCParamSets ps;
        memset(&ps, 0, sizeof(HEVCParamSets));
        HEVCSEI sei;
        memset(&sei, 0, sizeof(HEVCSEI));
        const HEVCPPS *pps = NULL;
        const HEVCSPS *sps = NULL;
        const HEVCVPS *vps = NULL;
        if ((ret = ff_hevc_decode_extradata(avctx->extradata, avctx->extradata_size, &ps, &sei,
                                            &is_avc, &nal_length_size,
                                            0, 1, avctx)) < 0) {
            avcodec_free_context(&avctx);
            return NULL;
        }
        for (i = 0; i < HEVC_MAX_PPS_COUNT; i++) {
            if (ps.pps_list[i]) {
                pps = (const HEVCPPS*)ps.pps_list[i]->data;
                break;
            }
        }

        if (pps)
            if (ps.sps_list[pps->sps_id])
                sps = (const HEVCSPS*)ps.sps_list[pps->sps_id]->data;

        if (pps && sps) {
            vps = (const HEVCVPS*)ps.vps_list[sps->vps_id]->data;
            const HEVCWindow *ow = &sps->output_window;
            unsigned int num = 0, den = 0;

            avctx->pix_fmt             = sps->pix_fmt;
            avctx->coded_width         = sps->width;
            avctx->coded_height        = sps->height;
            avctx->width               = sps->width  - ow->left_offset - ow->right_offset;
            avctx->height              = sps->height - ow->top_offset  - ow->bottom_offset;
            avctx->has_b_frames        = sps->temporal_layer[sps->max_sub_layers - 1].num_reorder_pics;
            avctx->profile             = sps->ptl.general_ptl.profile_idc;
            avctx->level               = sps->ptl.general_ptl.level_idc;

            avctx->sample_aspect_ratio = sps->vui.common.sar;

            if (sps->vui.common.video_signal_type_present_flag)
                avctx->color_range = sps->vui.common.video_full_range_flag ? AVCOL_RANGE_JPEG
                : AVCOL_RANGE_MPEG;
            else
                avctx->color_range = AVCOL_RANGE_MPEG;

            if (sps->vui.common.colour_description_present_flag) {
                avctx->color_primaries = sps->vui.common.colour_primaries;
                avctx->color_trc       = sps->vui.common.transfer_characteristics;
                avctx->colorspace      = sps->vui.common.matrix_coeffs;
            } else {
                avctx->color_primaries = AVCOL_PRI_UNSPECIFIED;
                avctx->color_trc       = AVCOL_TRC_UNSPECIFIED;
                avctx->colorspace      = AVCOL_SPC_UNSPECIFIED;
            }

            if (vps->vps_timing_info_present_flag) {
                num = vps->vps_num_units_in_tick;
                den = vps->vps_time_scale;
            } else if (sps->vui.vui_timing_info_present_flag) {
                num = sps->vui.vui_num_units_in_tick;
                den = sps->vui.vui_time_scale;
            } else {
                av_log(NULL, AV_LOG_ERROR, "timing_info_present_flag not set , use default timing\n");
            }

            if (num != 0 && den != 0)
                av_reduce(&avctx->framerate.den, &avctx->framerate.num,
                          num, den, 1 << 30);
            if (avctx->framerate.den)
                avctx->time_base = av_inv_q(av_mul_q(avctx->framerate, (AVRational){avctx->ticks_per_frame, 1}));
        } else{
            ff_hevc_ps_uninit(&ps);
            avcodec_free_context(&avctx);
            return NULL;
        }
        ff_hevc_ps_uninit(&ps);
    } else {
        av_log(NULL, AV_LOG_ERROR, "%s: unsupport codec id = %d\n", __func__, codecpar->codec_id);
        avcodec_free_context(&avctx);
        return NULL;
    }

    av_log(NULL, AV_LOG_DEBUG, "width = %d, height = %d\n",
           avctx->width,
           avctx->height);

    av_log(NULL, AV_LOG_DEBUG, "time_base= {%d,%d}, framerate = {%d,%d}\n",
           avctx->time_base.num,
           avctx->time_base.den,
           avctx->framerate.num,
           avctx->framerate.den);
    avctx->pix_fmt = AV_PIX_FMT_YUV420P;
    avctx->codec_type = AVMEDIA_TYPE_VIDEO;

    if (avctx->width > FF_MAX_CODEC_WIDTH || avctx->height > FF_MAX_CODEC_HEIGHT ||
        avctx->width <= 0   || avctx->height <= 0) {
        av_log(NULL, AV_LOG_ERROR,  "Error resolution: %dx%d\n", avctx->width, avctx->height);
        avcodec_free_context(&avctx);
        return NULL;
    }

    return avctx;
}

static
AVCodecContext * create_audio_decoder_from_codecpar (AVCodecParameters * codecpar)  {
    int ret = 0;
    const AVCodec * codec = NULL;
    AVCodecContext * avctx = NULL;
    MPEG4AudioConfig m4ac;
    memset(&m4ac, 0, sizeof(m4ac));

    if (!codecpar || !codecpar->extradata || !codecpar->extradata_size)
        return NULL;

    //Init Audio Stream
    if ((codec = avcodec_find_decoder(codecpar->codec_id)) == NULL)
        return NULL;

    if ((avctx = avcodec_alloc_context3(codec)) == NULL)
        return NULL;

    avctx->extradata_size = codecpar->extradata_size + AV_INPUT_BUFFER_PADDING_SIZE;
    avctx->extradata = av_mallocz(avctx->extradata_size);
    if (!avctx->extradata) {
        avcodec_free_context(&avctx);
        return NULL;
    }
    memcpy(avctx->extradata, codecpar->extradata, avctx->extradata_size);


    //sizeof(AudioSpecificConfig) >= 2
    if (avctx->extradata_size < 2) {
        av_log(NULL, AV_LOG_ERROR, "Wrong audio extradata length\n");
        avcodec_free_context(&avctx);
        return NULL;
    }

    if ((ret = avpriv_mpeg4audio_get_config2(&m4ac,
                                             avctx->extradata,
                                             avctx->extradata_size,
                                             1, avctx)) < 0) {
        avcodec_free_context(&avctx);
        return NULL;
    }

    av_log(NULL, AV_LOG_DEBUG, "sample_rate = %d, channels = %d\n",m4ac.sample_rate, m4ac.channels);

    avctx->sample_rate = m4ac.sample_rate;
    avctx->bits_per_coded_sample = 16;
    avctx->time_base = (AVRational){1, m4ac.sample_rate};
    avctx->sample_fmt = AV_SAMPLE_FMT_FLTP;
    avctx->codec_type = AVMEDIA_TYPE_AUDIO;
#if FF_API_OLD_CHANNEL_LAYOUT
FF_DISABLE_DEPRECATION_WARNINGS
    avctx->channels = m4ac.channels;
    avctx->channel_layout = av_get_default_channel_layout(avctx->channels);
FF_ENABLE_DEPRECATION_WARNINGS
#endif
    av_channel_layout_default(&avctx->ch_layout, m4ac.channels);

    avctx->frame_size = m4ac.frame_length_short ? 960 : 1024;
    avctx->frame_size <<= (m4ac.sbr == 1) ? m4ac.ext_sample_rate > m4ac.sample_rate : 0;


    if (avctx->sample_rate > FF_MAX_CODEC_SAMPLERATE ||
        avctx->sample_rate <= 0) {
        av_log(NULL, AV_LOG_ERROR,  "Error sample rate: %d\n", avctx->sample_rate);
        avcodec_free_context(&avctx);
        return NULL;
    }

    return avctx;
}

// must be called after avformat_open_input
int av_try_find_stream_info(AVFormatContext *ic, AVDictionary **options) {
    FF_DISABLE_DEPRECATION_WARNINGS
    int ret = 0;
    int nb_packets = 0;
    AVCodecContext * avctx[IJK_PROBE_MAX_CTX_COUNT] = {0};

    const char * iformat_name = NULL;
    if (ic && ic->iformat && ic->iformat->name) {
        if (ic->iformat->read_header2) {
            iformat_name = ic->iformat->name;
            if (!strcmp(iformat_name, "concat")) {
                ;
            } else if (!strcmp(iformat_name, "dash")) {
                ;
            } else if (!strcmp(iformat_name, "ijkdash")) {
                ;
            } else if (!strcmp(iformat_name, "ijklivehook")) {
                ;
            } else {
                iformat_name = NULL;
            }
        } else {
            iformat_name = ic->iformat->name;
            if (!strcmp(iformat_name, "mov,mp4,m4a,3gp,3g2,mj2")) {
                ;
            } else if (!strcmp(iformat_name, "flv")) {
                ;
            } else {
                iformat_name = NULL;
            }
        }
    }

    if (!iformat_name) {
        // currently only support mp4/flv
        // TODO: mpegts
        ret = IJK_STREAM_INFO_NOT_SUPPORT;
        goto fail;
    }

    if (ic->iformat->read_header2) {
        // no need to do find stream info
        av_log(NULL, AV_LOG_INFO, "%s: skip\n", __func__);
        ret = 0;
        goto fail;
    }

    // use missing streams for probe
    int *missing_streams = av_opt_ptr(ic->iformat->priv_class, ic->priv_data, "missing_streams");
    if (missing_streams) {
        av_log(NULL, AV_LOG_INFO, "%s: use missing_streams = %d\n", __func__, *missing_streams);
        int64_t now = av_gettime();
        int64_t start_time = now;
        while ((*missing_streams)) {
            ret = av_try_read_frame(ic, &nb_packets, NULL, 1);
            if (ret < 0) {
                av_log(NULL, AV_LOG_ERROR, "%s: av_try_read_frame fail!\n", __func__);
                goto fail;
            }
            if (nb_packets >= IJK_MAX_PROBE_COUNT) {
                av_log(NULL, AV_LOG_ERROR, "%s: nb_packets fail!\n", __func__);
                ret = -1;
                goto fail;
            }
        }

        now = av_gettime();
        av_log(NULL, AV_LOG_INFO, "%s: probe streams done , nb_streams = %d, read packets: %d, duration = %lld\n", __func__, ic->nb_streams,
               nb_packets, now - start_time);
        // Now ic->streams has all streams
        if (ic->nb_streams > IJK_PROBE_MAX_CTX_COUNT) {
            ret = IJK_STREAM_INFO_UNKNOWN;
            goto fail;
        }
    }

    for (int i = 0; i < ic->nb_streams; i++) {
        AVStream * st = ic->streams[i];
        if (!st->codecpar->extradata) {
            av_log(NULL, AV_LOG_ERROR, "%s: stream %d extradata fail!\n", __func__, i);
            ret = IJK_STREAM_INFO_UNKNOWN;
            goto fail;
        }
        switch (st->codecpar->codec_type) {
            case AVMEDIA_TYPE_VIDEO:
                avctx[i] = create_video_decoder_from_codecpar(st->codecpar);
                // fix when ticks_per_frame > 1
                if (avctx[i])
                    st->r_frame_rate =  avctx[i]->framerate;
                break;
            case AVMEDIA_TYPE_AUDIO:
                avctx[i] = create_audio_decoder_from_codecpar(st->codecpar);
                break;
            default:
                av_log(NULL, AV_LOG_ERROR, "%s: stream %d ignore unsupported type %d!\n", __func__, i, st->codecpar->codec_type);
                break;
        }
        if (!avctx[i]) {
            av_log(NULL, AV_LOG_ERROR, "%s: stream %d avctx fail!\n", __func__, i);
            ret = IJK_STREAM_INFO_UNKNOWN;
            goto fail;
        }
    }

    for (int i = 0; i < ic->nb_streams; i++) {
        AVStream * st = ic->streams[i];
        st->discard = AVDISCARD_DEFAULT;
        //desperated
        //avcodec_copy_context(st->codec,     avctx[i]);
        //avcodec_copy_context(st->internal->avctx, avctx[i]);
        avcodec_parameters_from_context(st->codecpar, avctx[i]);
        avformat_add_coded_side_data(st, avctx[i]);
        avpriv_set_pts_info(st, st->pts_wrap_bits, st->time_base.num, st->time_base.den);
    }

    ret = 0;
fail:
    for (int i = 0; i < IJK_PROBE_MAX_CTX_COUNT; i++) {
        if (avctx[i])
            avcodec_free_context(&avctx[i]);
    }

    if (ret < 0) {
        ret = avformat_find_stream_info(ic, options);
    } else {
        av_update_stream_timings(ic);
    }

    FF_ENABLE_DEPRECATION_WARNINGS
    return ret;
}

#endif

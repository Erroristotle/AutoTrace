# RQ2.1 Ranked Verifier Cases

| Rank | CVE | Variable | Cohort | Tier | RejectFn | Recovery | Escape | Exact | FuncHit | Statement |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | CVE-2018-13300 | par | Layer 1 soft reject | A | avpriv_request_sample | same_function_retry | yes | yes | yes | av_log(avc, AV_LOG_WARNING, " is not implemented.. |
| 2 | CVE-2017-13005 | rp | Layer 1 hard reject | A | xid_map_enter | same_function_retry | no | yes | yes | xmep->proc = EXTRACT_32BITS(&rp->rm_call.cb_proc); |
| 3 | CVE-2011-1771 | private_data | Layer 1 soft reject | A | cifs_close | same_function_retry | yes | yes | yes | struct inode *inode = cifs_file->dentry->d_inode; |
| 4 | CVE-2014-9663 | length | Layer 1 soft reject | A | tt_cmap4_validate | same_function_retry | no | yes | yes | num_segs = TT_NEXT_USHORT( p ); |
| 5 | CVE-2016-10506 | rpx | Layer 1 soft reject | A | opj_pi_next_rpcl | outward_expansion | yes | yes | yes | if (!((pi->y % (OPJ_INT32)(comp->dy << rpy) == 0) |
| 6 | CVE-2008-3911 | len | Layer 1 soft reject | A | proc_do_xprt | same_function_retry | yes | yes | yes | if (__copy_to_user(buffer, tmpbuf, len)) |
| 7 | CVE-2017-13005 | cb_proc | Layer 1 hard reject | A | xid_map_enter | same_function_retry | no | yes | yes | xmep->proc = EXTRACT_32BITS(&rp->rm_call.cb_proc); |
| 8 | CVE-2017-7864 | face | Layer 1 hard reject | A | tt_size_reset | same_function_retry | no | yes | yes | metrics->ascender = FT_PIX_ROUND( FT_MulFix( face- |
| 9 | CVE-2012-2100 | s_log_groups_per_flex | Layer 1 soft reject | A | ext4_fill_flex_info | same_function_retry | no | yes | yes | groups_per_flex = 1 << sbi->s_log_groups_per_flex; |
| 10 | CVE-2014-9673 | len | Layer 1 hard reject | A | Mac_Read_POST_Resource | same_function_retry | no | yes | yes | pfb_len += temp + 6; |
| 11 | CVE-2014-9673 | pfb_pos | Layer 1 hard reject | A | Mac_Read_POST_Resource | same_function_retry | no | yes | yes | pfb_len += temp + 6; |
| 12 | CVE-2014-9673 | rlen | Layer 1 hard reject | A | Mac_Read_POST_Resource | same_function_retry | no | yes | yes | pfb_len += temp + 6; |
| 13 | CVE-2016-7908 | length | Layer 1 soft reject | A | mcf_fec_do_tx | same_function_retry | yes | yes | yes | while (1) { |
| 14 | CVE-2017-18344 | event | Layer 1 soft reject | A | common_timer_set | same_function_retry | no | yes | yes | nstr[notify & ~SIGEV_THREAD_ID] |
| 15 | CVE-2017-8363 | metadata | Layer 1 soft reject | A | sf_flac_meta_callback | same_function_retry | no | yes | yes | switch (metadata->data.stream_info.bits_per_sample |
| 16 | CVE-2018-8043 | start | Layer 1 soft reject | A | unimac_mdio_probe | same_function_retry | yes | yes | yes | priv->base = devm_ioremap(&pdev->dev, r->start, re |
| 17 | CVE-2012-1016 | rep | Layer 1 soft reject | A | pkinit_server_return_padata | same_function_retry | no | yes | yes | retval = pkinit_alg_agility_kdf(context, &secret, |
| 18 | CVE-2012-5669 | glyph_enc | Layer 1 soft reject | A | _bdf_parse_glyphs | same_function_retry | yes | yes | yes | if ( _bdf_glyph_modified( p->have, p->glyph_enc ) |
| 19 | CVE-2013-0848 | avctx | Layer 1 soft reject | A | decode_init | same_function_retry | no | yes | yes | s->temp[0]= av_mallocz(4*s->width + 16); |
| 20 | CVE-2013-0848 | width | Layer 1 soft reject | A | decode_init | same_function_retry | no | yes | yes | s->temp[0]= av_mallocz(4*s->width + 16); |
| 21 | CVE-2016-3178 | server | Layer 1 soft reject | A | processRequest | same_function_retry | no | yes | yes | memcpy(newserv->server, p, l); |
| 22 | CVE-2017-13039 | ep | Layer 1 soft reject | A | ikev2_t_print | failure | no | yes | yes | totlen = 4 + EXTRACT_16BITS(&p[2]); |
| 23 | CVE-2017-13039 | totlen | Layer 1 soft reject | A | ikev1_t_print | failure | no | yes | yes | totlen = 4 + EXTRACT_16BITS(&p[2]); |
| 24 | CVE-2017-8064 | name | Layer 1 hard reject | A | dvb_usbv2_disconnect | same_function_retry | no | yes | yes | struct device dev = d->udev->dev; |
| 25 | CVE-2018-10768 | inkList | Layer 1 soft reject | A | AnnotInk::draw | same_function_retry | no | yes | yes | if (path->getCoordsLength() != 0) { |
| 26 | CVE-2018-11379 | file_name | Layer 1 hard reject | A | get_debug_info | same_function_retry | no | yes | yes | get_nb10 (dbg_data, &nb10_hdr); |
| 27 | CVE-2018-11384 | len | Layer 1 soft reject | A | sh_op | same_function_retry | no | yes | yes | op_MSB = anal->big_endian? data[0]: data[1]; |
| 28 | CVE-2018-14395 | channels | Layer 1 soft reject | A | mov_write_audio_tag | same_function_retry | yes | yes | yes | avio_wb32(pb, track->sample_size / track->par->cha |
| 29 | CVE-2018-16542 | osp | Layer 1 soft reject | A | gs_call_interp | same_function_retry | no | yes | yes | *++osp = *perror_object; |
| 30 | CVE-2018-8905 | op | Layer 1 soft reject | A | LZWDecodeCompat | same_function_retry | yes | yes | yes | *--tp = codep->value; |

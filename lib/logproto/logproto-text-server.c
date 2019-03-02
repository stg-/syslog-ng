/*
 * Copyright (c) 2002-2012 Balabit
 * Copyright (c) 1998-2012 Balázs Scheidler
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * As an additional exemption you are allowed to compile & link against the
 * OpenSSL libraries as published by the OpenSSL project. See the file
 * COPYING for details.
 *
 */
#include "logproto-text-server.h"
#include "messages.h"

#include <string.h>

/*
 * log_proto_get_fixed_encoding_scale:
 *
 * This function returns the number of bytes of a single character in the
 * encoding specified by the @encoding parameter, provided it is listed in
 * the limited set hard-wired in the fixed_encodings array above.
 *
 * syslog-ng sometimes needs to calculate the size of the original, raw data
 * that relates to its already utf8 converted input buffer.  For that the
 * slow solution is to actually perform the utf8 -> raw conversion, however
 * since we don't really need the actual conversion, just the size of the
 * data in bytes we can be faster than that by multiplying the number of
 * input characters with the size of the character in the known
 * fixed-length-encodings in the list above.
 *
 * This function returns 0 if the encoding is not known, in which case the
 * slow path is to be executed.
 */
gint
log_proto_get_char_size_for_fixed_encoding(const gchar *encoding)
{
  static struct
  {
    const gchar *prefix;
    gint scale;
  } fixed_encodings[] =
  {
    { "ascii", 1 },
    { "us-ascii", 1 },
    { "iso-8859", 1 },
    { "iso8859", 1 },
    { "latin", 1 },
    { "ucs2", 2 },
    { "ucs-2", 2 },
    { "ucs4", 4 },
    { "ucs-4", 4 },
    { "koi", 1 },
    { "unicode", 2 },
    { "windows", 1 },
    { "wchar_t", sizeof(wchar_t) },
    { NULL, 0 }
  };
  gint scale = 0;
  gint i;

  for (i = 0; fixed_encodings[i].prefix; i++)
    {
      if (strncasecmp(encoding, fixed_encodings[i].prefix, strlen(fixed_encodings[i].prefix)) == 0)
        {
          scale = fixed_encodings[i].scale;
          break;
        }
    }
  return scale;
}


static LogProtoPrepareAction
log_proto_text_server_prepare(LogProtoServer *s, GIOCondition *cond, gint *timeout)
{
  LogProtoTextServer *self = (LogProtoTextServer *) s;
  gboolean avail;

  LogProtoPrepareAction action = log_proto_buffered_server_prepare(s, cond, timeout);
  if (action != LPPA_POLL_IO)
    return action;

  avail = (self->cached_eol_pos != 0);
  return avail ? LPPA_FORCE_SCHEDULE_FETCH : LPPA_POLL_IO;
}

static void
log_proto_text_server_maybe_realloc_reverse_buffer(LogProtoTextServer *self, gsize buffer_length)
{
  if (self->reverse_buffer_len >= buffer_length)
    return;

  /* we free and malloc, since we never need the data still in reverse buffer */
  g_free(self->reverse_buffer);
  self->reverse_buffer_len = buffer_length;
  self->reverse_buffer = g_malloc(buffer_length);
}

/*
 * returns the number of bytes that represent the UTF8 encoding buffer
 * in the original encoding that the user specified.
 *
 * NOTE: this is slow, but we only call this for the remainder of our
 * buffer (e.g. the partial line at the end of our last chunk of read
 * data). Also, this is only invoked if the file uses an encoding.
 */
static gsize
log_proto_text_server_get_raw_size_of_buffer(LogProtoTextServer *self, const guchar *buffer, gsize buffer_len)
{
  gchar *out;
  const guchar *in;
  gsize avail_out, avail_in;
  gint ret;

  if (self->reverse_convert == ((GIConv) -1) && !self->convert_scale)
    {
      /* try to speed up raw size calculation by recognizing the most
       * prominent character encodings and in the case the encoding
       * uses fixed size characters set that in self->convert_scale,
       * which in turn will speed up the reversal of the UTF8 buffer
       * size to raw buffer sizes.
       */
      self->convert_scale = log_proto_get_char_size_for_fixed_encoding(self->super.super.options->encoding);
      if (self->convert_scale == 0)
        {
          /* this encoding is not known, do the conversion for real :( */
          self->reverse_convert = g_iconv_open(self->super.super.options->encoding, "utf-8");
        }
    }

  if (self->convert_scale)
    return g_utf8_strlen((gchar *) buffer, buffer_len) * self->convert_scale;


  /* Multiplied by 6, because 1 character can be maximum 6 bytes in UTF-8 encoding */
  log_proto_text_server_maybe_realloc_reverse_buffer(self, buffer_len * 6);

  avail_out = self->reverse_buffer_len;
  out = self->reverse_buffer;

  avail_in = buffer_len;
  in = buffer;

  ret = g_iconv(self->reverse_convert, (gchar **) &in, &avail_in, &out, &avail_out);
  if (ret == (gsize) -1)
    {
      /* oops, we cannot reverse that we ourselves converted to UTF-8,
       * this is simply impossible, but never say never */
      msg_error("Internal error, couldn't reverse the internal UTF8 string to the original encoding",
                evt_tag_printf("buffer", "%.*s", (gint) buffer_len, buffer));
      return 0;
    }
  else
    {
      return self->reverse_buffer_len - avail_out;
    }
}

static gint
log_proto_text_server_accumulate_line_method(LogProtoTextServer *self, const guchar *msg, gsize msg_len,
                                             gssize consumed_len)
{
  return LPT_CONSUME_LINE | LPT_EXTRACTED;
}

static void
log_proto_text_server_split_buffer(LogProtoTextServer *self, LogProtoBufferedServerState *state,
                                   const guchar *buffer_start, gsize buffer_bytes)
{
  gsize raw_split_size;

  /* buffer is not full, but no EOL is present, move partial line
   * to the beginning of the buffer to make space for new data.
   */

  memmove(self->super.buffer, buffer_start, buffer_bytes);
  state->pending_buffer_pos = 0;
  state->pending_buffer_end = buffer_bytes;

  if (G_UNLIKELY(self->super.pos_tracking))
    {
      /* NOTE: we modify the current file position _after_ updating
         buffer_pos, since if we crash right here, at least we
         won't lose data on the next restart, but rather we
         duplicate some data */


      if (self->super.super.options->encoding)
        raw_split_size = log_proto_text_server_get_raw_size_of_buffer(self, buffer_start, buffer_bytes);
      else
        raw_split_size = buffer_bytes;

      state->pending_raw_stream_pos += (gint64) (state->pending_raw_buffer_size - raw_split_size);
      state->pending_raw_buffer_size = raw_split_size;

      msg_trace("Buffer split",
                evt_tag_int("raw_split_size", raw_split_size),
                evt_tag_int("buffer_bytes", buffer_bytes));
    }

}
//
//void ALARMhandler(LogProtoTextServer *self, LogProtoBufferedServerState *state,
//                                  const guchar *buffer_start, const guchar *eol, gsize *msg_len, int sig)

void ALARMhandler(int sig)
{
  signal(SIGALRM, SIG_IGN);          /* ignore this signal       */
  /* value = "BYE";
  msg_debug(value);*/
  rewind_extracted();

  signal(SIGALRM, ALARMhandler);     /* reinstall the handler    */
}

static gboolean
log_proto_text_server_try_extract(LogProtoTextServer *self, LogProtoBufferedServerState *state,
                                  const guchar *buffer_start, gsize buffer_bytes, const guchar *eol, const guchar **msg, gsize *msg_len)
{
  gint verdict;
  guint32 next_line_pos;
  guint32 next_eol_pos = 0;

  next_line_pos = eol + 1 - self->super.buffer;
  if (state->pending_buffer_end != next_line_pos)
    {
      msg_debug("STG: state->pending_buffer_end != next_line_pos");
      const guchar *eom;

      /* we have some more data in the buffer, check if we have a
       * subsequent EOL there.  It indicates whether we need to
       * read further data, or the buffer already contains a
       * complete line */

      eom = find_eom(self->super.buffer + next_line_pos, state->pending_buffer_end - next_line_pos);
      if (eom)
        msg_debug("STG: eom");
        next_eol_pos = eom - self->super.buffer;
    }

  *msg_len = eol - buffer_start;
  *msg = buffer_start;

  verdict = log_proto_text_server_accumulate_line(self, *msg, *msg_len, self->consumed_len);
  if (verdict & LPT_EXTRACTED)
    {
      msg_debug("STG: verdict & LPT_EXTRACTED");
      if (verdict & LPT_CONSUME_LINE)
        {
          msg_debug("  STG: verdict & LPT_CONSUME_LINE");
          gint drop_length = (verdict & LPT_CONSUME_PARTIAL_AMOUNT_MASK) >> LPT_CONSUME_PARTIAL_AMOUNT_SHIFT;

          state->pending_buffer_pos = next_line_pos;
          self->cached_eol_pos = next_eol_pos;
          if (drop_length)
            *msg_len -= drop_length;
        }
      else if (verdict & LPT_REWIND_LINE)
        {
          msg_debug("  STG: verdict & LPT_REWIND_LINE");

          if (self->consumed_len >= 0)
            *msg_len = self->consumed_len;
          else
            *msg_len = 0;

          state->pending_buffer_pos = (buffer_start + self->consumed_len + 1) - self->super.buffer;
          self->cached_eol_pos = eol - self->super.buffer;
        }
      else
        {
          msg_debug("  STG: else");
          g_assert_not_reached();
      }
      self->consumed_len = -1;
    }
  else if (verdict & LPT_WAITING)
    {
      /*
      int msec = 0, trigger = 10000;
      clock_t before = clock();
      msg_debug("STG: Waiting 10 seconds");
      do
        {
          clock_t difference = clock() - before;
          msec = difference * 1000 / CLOCKS_PER_SEC;
        }
      while (msec < trigger);
      */

      msg_debug("STG: verdict & LPT_WAITING");

      *msg = NULL;
      *msg_len = 0;
      if (verdict & LPT_CONSUME_LINE)
        {
          msg_debug("  STG: verdict & LPT_CONSUME_LINE");

          /* TODO: If there's a line in buffer,
            activate non-blocking timer=10sec event= LPT_REWIND_LINE | LPT_EXTRACTED */
          /*
          msg_debug("  STG: ", evt_tag_int("consumed_len",self->consumed_len));
          if (self->consumed_len > 0)
            {
              msg_debug("STG: BUFFER not empty");
              msg_debug("STG: Setting ALARM");
              signal(SIGALRM, ALARMhandler);
              alarm(10);
              msg_debug("STG: END Setting ALARM");
            }
          */

          /* TODO: loop waiting for new input line */

          int buffer_state = buffer_bytes;

//          int msec = 0, trigger = 5000;
//          clock_t before = clock();
//          msg_debug("STG: Waiting 10 seconds");
//          do
//            {
//              clock_t difference = clock() - before;
//              msec = difference * 1000 / CLOCKS_PER_SEC;
//            }
//          while (buffer_bytes == buffer_state && msec < trigger);

//          if (msec < trigger)
//          {
//          /* TODO: new line arrived just in time */
//          msg_debug("STG: new line arrived just in time");
//          }
//          else
//          {
//          /* TODO: time expired! */
//          msg_debug("STG: time expired");
//          }

          /*
          if (log_proto_text_server_try_extract(self, state, buffer_start, buffer_bytes, eol, msg, msg_len))
            {
              msg_debug("STG: EXTRACTION POSSIBLE");
            }
          else
            {
              msg_debug("STG: EXTRACTION NOT POSSIBLE");
            }
            */

          // TODO: !!! To inject a new line?
          // self = LogProtoTextServer which has a LogProtoBufferedServer (super), which has a
          //  LogProtoServer (super) which has a LogTransport (transport) which has an gint fd. Can we write into that fd??
          msg_debug("  STG3: ", evt_tag_int("fd",self->super.super.transport->fd));

          //fprintf(self->super.super.transport->fd, "TEST STG AAAAABC");

          // log_transport_write
          // log_transport_read

          strcat(self->super.buffer, "A");
          msg_debug("  STG3: ", evt_tag_int("next_line_pos",next_line_pos));
          msg_debug("  STG3: ", evt_tag_int("pending_buffer_end",state->pending_buffer_end));
          msg_debug("  STG3: ", evt_tag_int("consumed_len",self->consumed_len));
          msg_debug("  STG3: ", evt_tag_int("buffer_bytes",buffer_bytes));
          msg_debug("  STG3: ", evt_tag_int("buffer_start",buffer_start));
          msg_debug("  STG3: ", evt_tag_str("eol",eol));
          if (buffer_bytes != 0)
          {
            msg_debug("STGG: message comming!!");
          }

          /*
          msg_debug("STGG: REWIND IT!!")
          if (self->consumed_len >= 0)
            *msg_len = self->consumed_len;
          else
            *msg_len = 0;

          state->pending_buffer_pos = (buffer_start + self->consumed_len + 1) - self->super.buffer;
          self->cached_eol_pos = eol - self->super.buffer;
          msg_debug("STGG: END REWIND IT!!")
          */

          /* TODO: This handles the incoming and outgoing??? */
          self->cached_eol_pos = next_eol_pos;
          self->consumed_len = eol - buffer_start;

          msg_debug("  STG4: ", evt_tag_int("consumed_len",self->consumed_len));
          msg_debug("  STG4: ", evt_tag_int("buffer_bytes",buffer_bytes));
          msg_debug("  STG4: ", evt_tag_int("buffer_start",buffer_start));
          msg_debug("  STG4: ", evt_tag_str("eol",eol));

          msg_debug("  STG: ENDIF verdict & LPT_CONSUME_LINE");
        }
      else
        {
          msg_debug("  STG: else");
          /* when we are waiting for another line, the current one
           * can't be rewinded, so LPT_REWIND_LINE is not valid */
          g_assert_not_reached();
        }
      msg_debug("STG: return FALSE");
      return FALSE;
    }
  else
    {
      msg_debug("STG: else");
      g_assert_not_reached();
    }
  msg_debug("STG: return TRUE");
  return TRUE;
}

static gboolean
log_proto_text_server_extract(LogProtoTextServer *self, LogProtoBufferedServerState *state, const guchar *buffer_start,
                              gsize buffer_bytes, const guchar *eol, const guchar **msg, gsize *msg_len)
{
  do
    {
      msg_debug("STG: Start do");
      msg_debug("  STG5: ", evt_tag_int("cached_eol_pos",self->cached_eol_pos));
      msg_debug("  STG5: ", evt_tag_str("super.buffer",self->super.buffer));
      alarm(0);
      msg_debug("STG: Alarm deactivated");
      if (log_proto_text_server_try_extract(self, state, buffer_start, buffer_bytes, eol, msg, msg_len))
        {
        msg_debug("STG: try extract OK");
        return TRUE;
        }
      msg_debug("STG: try extract FAILED");
      eol = self->super.buffer + self->cached_eol_pos;
    }
  while (self->cached_eol_pos > 0);
  msg_debug("STG:quit while");
  return FALSE;
}

static void
log_proto_text_server_remove_trailing_newline(const guchar **msg, gsize *msg_len)
{
  const guchar *msg_start = (*msg);
  const guchar *msg_end = msg_start + (*msg_len);

  /* msg_end points at the newline character. A \r or \0 may precede
   * this which should be removed from the message body */

  while ((msg_end > msg_start) && (msg_end[-1] == '\r' || msg_end[-1] == '\n' || msg_end[-1] == 0))
    msg_end--;
  *msg_len = msg_end - msg_start;
}


static inline void
log_proto_text_server_yield_whole_buffer_as_message(LogProtoTextServer *self, LogProtoBufferedServerState *state,
                                                    const guchar *buffer_start, gsize buffer_bytes, const guchar **msg, gsize *msg_len)
{
  /* no EOL, our buffer is full, no way to move forward, return
   * everything we have in our buffer. */

  *msg = buffer_start;
  *msg_len = buffer_bytes;
  self->consumed_len = -1;
  state->pending_buffer_pos = (*msg) + (*msg_len) - self->super.buffer;
}

static inline const guchar *
log_proto_text_server_locate_next_eol(LogProtoTextServer *self, LogProtoBufferedServerState *state,
                                      const guchar *buffer_start, gsize buffer_bytes)
{
  const guchar *eol;

  if (self->cached_eol_pos)
    {
      /* previous invocation was nice enough to save a cached EOL
       * pointer, no need to look it up again */

      eol = self->super.buffer + self->cached_eol_pos;
      self->cached_eol_pos = 0;
    }
  else
    {
      eol = find_eom(buffer_start + self->consumed_len + 1, buffer_bytes - self->consumed_len - 1);
    }
  return eol;
}

static gboolean
log_proto_text_server_message_size_too_large(LogProtoTextServer *self, gsize buffer_bytes)
{
  return buffer_bytes >= self->super.super.options->max_msg_size;
}

/**
 * log_proto_text_server_fetch_from_buffer:
 * @self: LogReader instance
 * @saddr: socket address to be assigned to new messages (consumed!)
 * @flush: whether to flush the input buffer
 * @msg_counter: the number of messages processed in the current poll iteration
 *
 * Returns TRUE if a message was found in the buffer, FALSE if we need to read again.
 **/
static gboolean
log_proto_text_server_fetch_from_buffer(LogProtoBufferedServer *s, const guchar *buffer_start, gsize buffer_bytes,
                                        const guchar **msg, gsize *msg_len)
{
  msg_debug("STG: log_proto_text_server_fetch_from_buffer");
  LogProtoTextServer *self = (LogProtoTextServer *) s;
  LogProtoBufferedServerState *state = log_proto_buffered_server_get_state(&self->super);
  gboolean result = FALSE;

  const guchar *eol = log_proto_text_server_locate_next_eol(self, state, buffer_start, buffer_bytes);

  if (!eol)
    {
      if (log_proto_text_server_message_size_too_large(self, buffer_bytes)
          || log_proto_buffered_server_is_input_closed(&self->super))
        {
          log_proto_text_server_yield_whole_buffer_as_message(self, state, buffer_start, buffer_bytes, msg, msg_len);
        }
      else
        {
          log_proto_text_server_split_buffer(self, state, buffer_start, buffer_bytes);
          goto exit;
        }
    }
  else if (!log_proto_text_server_extract(self, state, buffer_start, buffer_bytes, eol, msg, msg_len))
    {
      if (log_proto_text_server_message_size_too_large(self, buffer_bytes))
        {
          log_proto_text_server_yield_whole_buffer_as_message(self, state, buffer_start, buffer_bytes, msg, msg_len);
        }
      else
        {
          log_proto_text_server_split_buffer(self, state, buffer_start, buffer_bytes);
          goto exit;
        }
    }

  log_proto_text_server_remove_trailing_newline(msg, msg_len);
  result = TRUE;

exit:
  log_proto_buffered_server_put_state(&self->super);
  return result;
}

static void
log_proto_text_server_free(LogProtoServer *s)
{
  LogProtoTextServer *self = (LogProtoTextServer *) s;
  if (self->reverse_convert != (GIConv) -1)
    g_iconv_close(self->reverse_convert);

  g_free(self->reverse_buffer);
  log_proto_buffered_server_free_method(&self->super.super);
}

void rewind_extracted()
{
  /*
  if (self->consumed_len >= 0)
    *msg_len = self->consumed_len;
  else
    *msg_len = 0;

  state->pending_buffer_pos = (buffer_start + self->consumed_len + 1) - self->super.buffer;
  self->cached_eol_pos = eol - self->super.buffer;
  */
  //log_proto_text_server_fetch_from_buffer;

  msg_debug("STG: ALERT!!!");
  msg_debug("STG: LPT_REWIND_LINE | LPT_EXTRACTED");
}

void
log_proto_text_server_init(LogProtoTextServer *self, LogTransport *transport, const LogProtoServerOptions *options)
{
  log_proto_buffered_server_init(&self->super, transport, options);
  self->super.super.prepare = log_proto_text_server_prepare;
  self->super.super.free_fn = log_proto_text_server_free;
  self->super.fetch_from_buffer = log_proto_text_server_fetch_from_buffer;
  self->accumulate_line = log_proto_text_server_accumulate_line_method;
  self->super.stream_based = TRUE;
  self->reverse_convert = (GIConv) -1;
  self->consumed_len = -1;
}

LogProtoServer *
log_proto_text_server_new(LogTransport *transport, const LogProtoServerOptions *options)
{
  LogProtoTextServer *self = g_new0(LogProtoTextServer, 1);

  log_proto_text_server_init(self, transport, options);
  return &self->super.super;
}

#include <glib.h>
#include <stdio.h>

#pragma once

#define BOOL_CHECK(func_call)                                                  \
   do {                                                                        \
      gboolean func_ret = (func_call);                                         \
      if (!func_ret) {                                                         \
         fp_err("Error in %d:" #func_call, __LINE__);                          \
         ret = FALSE;                                                          \
         goto error;                                                           \
      }                                                                        \
   } while (0)
#define WRITTEN_CHECK(condition)                                               \
   do {                                                                        \
      if (!(condition)) {                                                      \
         fp_err("Writing error occurred in %d:%s", __LINE__, __FUNCTION__);    \
         ret = FALSE;                                                          \
         goto error;                                                           \
      }                                                                        \
   } while (0)
#define READ_OK_CHECK(condition)                                               \
   do {                                                                        \
      if (!(condition)) {                                                      \
         fp_err("Reading error occurred in %d:%s", __LINE__, __FUNCTION__);    \
         ret = FALSE;                                                          \
         goto error;                                                           \
      }                                                                        \
   } while (0)
#define NULL_CHECK(ptr)                                                        \
   do {                                                                        \
      if ((ptr) == NULL) {                                                     \
         fp_err("Error: NULL pointer in %s at line %d", __func__, __LINE__);   \
         return = FALSE;                                                       \
      }                                                                        \
   } while (0)

static void reverse_array(guint8 *arr, gsize size)
{
   gint start = 0;
   gint end = size - 1;
   gint temp;

   while (start < end) {
      // Swap the elements at start and end
      temp = arr[start];
      arr[start] = arr[end];
      arr[end] = temp;

      // Move towards the middle
      start++;
      end--;
   }
}

static void print_array(const guint8 *arr, const gint size)
{
   for (int i = 0; i < size; i++) {
      printf("%02x", arr[i]);
   }
   printf("\n"); // Print a newline at the end
}

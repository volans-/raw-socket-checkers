/*
 * Software:    raw-socket-checkers is a collection of network checks suitable
 *              to be used as a check for load balancers in direct routing
 *              mode (LVS-DR) to ensure that the real server is indeed
 *              answering to packets with the VIRTUAL_IP destination IP, see
 *              <https://github.com/volans-/raw-socket-checkers>
 *
 * Part:        Common library.
 *
 * Author:      Riccardo Coccioli, <volans-@users.noreply.github.com>
 *
 *              This program is distributed in the hope that it will be useful,
 *              but WITHOUT ANY WARRANTY; without even the implied warranty of
 *              MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *              See the GNU General Public License for more details:
 *              <http://www.gnu.org/licenses/>
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License or (at your option) any later version.
 *
 * Copyright (C) 2016 Riccardo Coccioli, <volans-@users.noreply.github.com>
 */

#include <stdarg.h> /* va_* type and functions */

#include "common.h"

/*
 * Check and set the verbosity level
 *
 * Return 1 if the verbosity allow a message of verbosity_level, 0 otherwise.
 * When new_verbosity is > 0, set also the new verbosity level.
 */
uint8_t
check_verbosity(verbosity_level_type verbosity_level,
    verbosity_level_type new_verbosity)
{

    /* Verbosity level across the whole execution */
    static verbosity_level_type verbosity = 0;

    if (new_verbosity > RSC_LL_HIGH)
        new_verbosity = RSC_LL_HIGH;

    if (new_verbosity != RSC_NOOP_VERBOSITY)
        verbosity = new_verbosity;

    return (verbosity >= verbosity_level);
}

/*
 * Print line to stdout or stderr based on verbosity
 *
 * The optional parameters are passed directly to printf
 */
void
rsc_log(verbosity_level_type level, FILE *output, char *message, ...)
{
    va_list arguments;

    /* Print the error message */
    if (message != NULL && check_verbosity(level, RSC_NOOP_VERBOSITY) == 1) {
        va_start(arguments, message);
        vfprintf(output, message, arguments);
        va_end(arguments);
    }
}

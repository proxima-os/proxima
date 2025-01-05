#ifndef HYDROGEN_FCNTL_H
#define HYDROGEN_FCNTL_H

#define O_RDONLY (1u << 0)
#define O_WRONLY (1u << 1)
#define O_EXEC (1u << 2)
#define O_SEARCH O_EXEC
#define O_RDWR (O_RDONLY | O_WRONLY)
#define O_ACCMODE (O_EXEC | O_WRONLY | O_RDONLY)
#define O_APPEND (1u << 3)

#define O_CREAT (1u << 16)
#define O_DIRECTORY (1u << 17)
#define O_NODIR (1u << 18)
#define O_EXCL (1u << 19)
#define O_NOFOLLOW (1u << 20)
#define O_TRUNC (1u << 21)
#define O_CLOEXEC (1u << 22)
#define O_CLOFORK (1u << 23)

#define FD_CLOEXEC (1u << 0)
#define FD_CLOFORK (1u << 1)

#endif // HYDROGEN_FCNTL_H

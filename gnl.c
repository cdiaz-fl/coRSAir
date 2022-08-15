#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include	"coRSAir.h"


char	*find_next_line(char *holder)
{
	char	*line;
	size_t	len;

	if (ft_strchr(holder, '\n'))
	{
		len = strlen(ft_strchr(holder, '\n'));
		line = ft_substr(holder, 0, strlen(holder) - len + 1);
	}
	else
		line = ft_strdup(holder);
	return (line);
}

char	*save_holder(char *buf, char *holder)
{
	char	*holder_new;

	if (!holder)
		holder_new = ft_strdup(buf);
	else
	{
		holder_new = ft_strjoin(holder, buf);
		free(holder);
	}
	free(buf);
	return (holder_new);
}

char	*new_holder(char *holder)
{
	int		len;
	char	*new_holder;

	if (!(ft_strchr(holder, '\n')))
	{
		free(holder);
		return (NULL);
	}
	len = strlen(holder) - strlen(ft_strchr(holder, '\n'));
	new_holder = ft_strdup(&holder[len + 1]);
	free(holder);
	return (new_holder);
}

char	*read_file(int fd, char *holder)
{
	char	*buf;
	int		num_bytes;

	num_bytes = 1;
	while (num_bytes > 0 && !ft_strchr(holder, '\n'))
	{
		buf = (char *)malloc(1 + 1);
		if (!buf)
			return (NULL);
		num_bytes = read(fd, buf, 1);
		if (num_bytes == -1 || (!num_bytes && !holder))
		{
			free(buf);
			return (NULL);
		}
		if (num_bytes == 0 && *holder == 0)
		{
			free(holder);
			free(buf);
			return (NULL);
		}
		buf[num_bytes] = '\0';
		holder = save_holder(buf, holder);
	}
	return (holder);
}

char	*get_next_line(int fd)
{
	char		*line;
	static char	*holder;

	holder = read_file(fd, holder);
	if (!holder)
		return (NULL);
	line = find_next_line(holder);
	holder = new_holder(holder);
	return (line);
}


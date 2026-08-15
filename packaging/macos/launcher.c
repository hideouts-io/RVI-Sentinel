#include <errno.h>
#include <limits.h>
#include <mach-o/dyld.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void fail(const char *message) {
    fprintf(stderr, "RVI-Sentinel launcher error: %s\n", message);
    exit(EXIT_FAILURE);
}

static void parent_directory(char *path) {
    char *separator = strrchr(path, '/');
    if (separator == NULL || separator == path) {
        fail("could not resolve the project directory from the application bundle");
    }
    *separator = '\0';
}

static void join_path(char *destination, size_t capacity, const char *root, const char *suffix) {
    int written = snprintf(destination, capacity, "%s/%s", root, suffix);
    if (written < 0 || (size_t)written >= capacity) {
        fail("a required project path exceeds PATH_MAX");
    }
}

int main(int argument_count, char *arguments[]) {
    char executable_path[PATH_MAX];
    uint32_t executable_path_size = sizeof(executable_path);
    if (_NSGetExecutablePath(executable_path, &executable_path_size) != 0) {
        fail("the application executable path exceeds PATH_MAX");
    }

    char project_directory[PATH_MAX];
    if (realpath(executable_path, project_directory) == NULL) {
        fprintf(stderr, "RVI-Sentinel launcher error: realpath failed: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }
    for (int level = 0; level < 5; level += 1) {
        parent_directory(project_directory);
    }

    char python_path[PATH_MAX];
    char gui_path[PATH_MAX];
    join_path(python_path, sizeof(python_path), project_directory, "venv/bin/python");
    join_path(gui_path, sizeof(gui_path), project_directory, "gui.py");
    if (access(python_path, X_OK) != 0) {
        fprintf(
            stderr,
            "RVI-Sentinel launcher error: GUI environment is not executable: %s: %s\n",
            python_path,
            strerror(errno)
        );
        return EXIT_FAILURE;
    }
    if (access(gui_path, R_OK) != 0) {
        fprintf(
            stderr,
            "RVI-Sentinel launcher error: GUI entry point is not readable: %s: %s\n",
            gui_path,
            strerror(errno)
        );
        return EXIT_FAILURE;
    }

    char **python_arguments = calloc((size_t)argument_count + 2, sizeof(char *));
    if (python_arguments == NULL) {
        fail("could not allocate the Python argument list");
    }
    python_arguments[0] = python_path;
    python_arguments[1] = gui_path;
    for (int index = 1; index < argument_count; index += 1) {
        python_arguments[index + 1] = arguments[index];
    }

    execv(python_path, python_arguments);
    fprintf(
        stderr,
        "RVI-Sentinel launcher error: could not start %s: %s\n",
        python_path,
        strerror(errno)
    );
    free(python_arguments);
    return EXIT_FAILURE;
}

#define _DARWIN_C_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <ctype.h>
#include <errno.h>
#include <math.h>
#include <ncurses.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if defined(__has_include)
#if __has_include(<sys/random.h>)
#include <sys/random.h>
#endif
#endif

#define MIN_LENGTH 1
#define MAX_LENGTH 128
#define MIN_WORDS 1
#define MAX_WORDS 32
#define HISTORY_MAX 100
#define EXPECTED_EFF_WORDS 7776
#define MAX_WORD_LEN 32
#define MAX_OUTPUT 1024

#ifdef PASSGEN_TEST
#define TEST_UNUSED __attribute__((unused))
#else
#define TEST_UNUSED
#endif

typedef enum {
    MODE_PASSWORD = 0,
    MODE_PASSPHRASE = 1
} GenerationMode;

typedef enum {
    HISTORY_HIDDEN = 0,
    HISTORY_LAST = 1,
    HISTORY_ALL = 2
} HistoryVisibility;

typedef enum {
    SEPARATOR_HYPHEN = 0,
    SEPARATOR_SPACE = 1,
    SEPARATOR_NONE = 2
} SeparatorMode;

typedef struct {
    int length;
    int uppercase;
    int lowercase;
    int digits;
    int symbols;
    int word_count;
    SeparatorMode separator_mode;
    GenerationMode mode;
} Settings;

typedef struct {
    char **items;
    size_t count;
} WordList;

typedef struct {
    char *items[HISTORY_MAX];
    size_t count;
} History;

typedef struct {
    Settings settings;
    WordList words;
    History history;
    HistoryVisibility history_visibility;
    size_t history_scroll;
    int output_visible;
    int help_visible;
    char current[MAX_OUTPUT];
    char status[160];
    int copied_flash;
} App;

static const char *UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
static const char *LOWER = "abcdefghijklmnopqrstuvwxyz";
static const char *DIGITS = "0123456789";
static const char *SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>?/";

static char *xstrdup(const char *s)
{
    size_t len = strlen(s) + 1;
    char *copy = malloc(len);
    if (copy != NULL) {
        memcpy(copy, s, len);
    }
    return copy;
}

static int secure_random_bytes(void *buf, size_t len)
{
    unsigned char *out = buf;
    size_t offset = 0;

    arc4random_buf(buf, len);

    while (offset < len) {
        unsigned char extra[256];
        size_t chunk = len - offset;
        if (chunk > sizeof(extra)) {
            chunk = sizeof(extra);
        }

        if (getentropy(extra, chunk) != 0) {
            return 0;
        }

        for (size_t i = 0; i < chunk; i++) {
            out[offset + i] ^= extra[i];
        }
        offset += chunk;
    }

    return 1;
}

static uint32_t random_u32(void)
{
    uint32_t value = 0;
    secure_random_bytes(&value, sizeof(value));
    return value;
}

static uint32_t random_uniform(uint32_t upper_bound)
{
    uint32_t min;
    uint32_t value;

    if (upper_bound < 2U) {
        return 0;
    }

    min = (uint32_t)(-upper_bound % upper_bound);
    do {
        value = random_u32();
    } while (value < min);

    return value % upper_bound;
}

static int append_charset(char *pool, size_t capacity, size_t *used, const char *chars)
{
    size_t add = strlen(chars);
    if (*used + add + 1 > capacity) {
        return 0;
    }
    memcpy(pool + *used, chars, add);
    *used += add;
    pool[*used] = '\0';
    return 1;
}

static size_t build_pool(const Settings *settings, char *pool, size_t capacity)
{
    size_t used = 0;
    pool[0] = '\0';
    if (settings->uppercase) {
        append_charset(pool, capacity, &used, UPPER);
    }
    if (settings->lowercase) {
        append_charset(pool, capacity, &used, LOWER);
    }
    if (settings->digits) {
        append_charset(pool, capacity, &used, DIGITS);
    }
    if (settings->symbols) {
        append_charset(pool, capacity, &used, SYMBOLS);
    }
    return used;
}

static double password_entropy_bits(const Settings *settings)
{
    char pool[128];
    size_t pool_size = build_pool(settings, pool, sizeof(pool));
    if (pool_size == 0) {
        return 0.0;
    }
    return (double)settings->length * log2((double)pool_size);
}

static int passphrase_word_count(const Settings *settings)
{
    int words = settings->word_count;
    if (words < 4) {
        words = MIN_WORDS;
    }
    if (words > MAX_WORDS) {
        words = MAX_WORDS;
    }
    return words;
}

static char passphrase_separator(const Settings *settings)
{
    if (settings->separator_mode == SEPARATOR_HYPHEN) {
        return '-';
    }
    if (settings->separator_mode == SEPARATOR_SPACE) {
        return ' ';
    }
    return '\0';
}

static TEST_UNUSED const char *passphrase_separator_label(const Settings *settings)
{
    if (settings->separator_mode == SEPARATOR_HYPHEN) {
        return "hyphens";
    }
    if (settings->separator_mode == SEPARATOR_SPACE) {
        return "spaces";
    }
    return "none";
}

static TEST_UNUSED const char *mode_label(const Settings *settings)
{
    return settings->mode == MODE_PASSWORD ? "Password" : "Passphrase";
}

static TEST_UNUSED const char *entropy_label(double bits)
{
    if (bits >= 80.0) {
        return "strong";
    }
    if (bits >= 50.0) {
        return "moderate";
    }
    return "weak";
}

static void cycle_passphrase_separator(Settings *settings)
{
    if (settings->separator_mode == SEPARATOR_HYPHEN) {
        settings->separator_mode = SEPARATOR_SPACE;
    } else if (settings->separator_mode == SEPARATOR_SPACE) {
        settings->separator_mode = SEPARATOR_NONE;
    } else {
        settings->separator_mode = SEPARATOR_HYPHEN;
    }
}

static double passphrase_entropy_bits(const Settings *settings, size_t word_count)
{
    int words = passphrase_word_count(settings);
    if (word_count == 0) {
        return 0.0;
    }
    return (double)words * log2((double)word_count);
}

static TEST_UNUSED double current_entropy_bits(const Settings *settings, size_t word_count)
{
    if (settings->mode == MODE_PASSPHRASE) {
        return passphrase_entropy_bits(settings, word_count);
    }
    return password_entropy_bits(settings);
}

static void adjust_length(Settings *settings, int delta)
{
    settings->length += delta;
    if (settings->length < MIN_LENGTH) {
        settings->length = MIN_LENGTH;
    }
    if (settings->length > MAX_LENGTH) {
        settings->length = MAX_LENGTH;
    }
}

static void adjust_word_count(Settings *settings, int delta)
{
    settings->word_count += delta;
    if (settings->word_count < MIN_WORDS) {
        settings->word_count = MIN_WORDS;
    }
    if (settings->word_count > MAX_WORDS) {
        settings->word_count = MAX_WORDS;
    }
}

static size_t history_visible_count(HistoryVisibility visibility, size_t count)
{
    if (visibility == HISTORY_HIDDEN || count == 0) {
        return 0;
    }
    if (visibility == HISTORY_LAST) {
        return 1;
    }
    return count < HISTORY_MAX ? count : HISTORY_MAX;
}

static void history_scroll_by(size_t *offset, size_t count, size_t viewport, int delta)
{
    size_t max_offset = 0;

    if (count > viewport) {
        max_offset = count - viewport;
    }

    if (delta < 0) {
        size_t amount = (size_t)(-delta);
        *offset = amount > *offset ? 0 : *offset - amount;
    } else {
        *offset += (size_t)delta;
        if (*offset > max_offset) {
            *offset = max_offset;
        }
    }
}

static int generate_password(const Settings *settings, char *out, size_t out_size)
{
    char pool[128];
    size_t pool_size = build_pool(settings, pool, sizeof(pool));

    if (pool_size == 0 || out_size <= (size_t)settings->length) {
        return 0;
    }

    for (int i = 0; i < settings->length; i++) {
        out[i] = pool[random_uniform((uint32_t)pool_size)];
    }
    out[settings->length] = '\0';
    return 1;
}

static int generate_passphrase(const Settings *settings, const WordList *words, char *out, size_t out_size)
{
    int count = passphrase_word_count(settings);
    size_t used = 0;

    if (words->count == 0) {
        return 0;
    }

    out[0] = '\0';
    for (int i = 0; i < count; i++) {
        const char *word = words->items[random_uniform((uint32_t)words->count)];
        size_t word_len = strlen(word);
        char separator = passphrase_separator(settings);
        size_t need = word_len + (i > 0 && separator != '\0' ? 1U : 0U);

        if (used + need + 1 > out_size) {
            return 0;
        }

        if (i > 0 && separator != '\0') {
            out[used++] = separator;
        }
        memcpy(out + used, word, word_len);
        used += word_len;
        out[used] = '\0';
    }

    return 1;
}

static TEST_UNUSED void history_clear(History *history)
{
    for (size_t i = 0; i < history->count; i++) {
        free(history->items[i]);
        history->items[i] = NULL;
    }
    history->count = 0;
}

static TEST_UNUSED void history_add(History *history, const char *value)
{
    char *copy = xstrdup(value);
    if (copy == NULL) {
        return;
    }

    if (history->count == HISTORY_MAX) {
        free(history->items[HISTORY_MAX - 1]);
        for (size_t i = HISTORY_MAX - 1; i > 0; i--) {
            history->items[i] = history->items[i - 1];
        }
    } else {
        for (size_t i = history->count; i > 0; i--) {
            history->items[i] = history->items[i - 1];
        }
        history->count++;
    }
    history->items[0] = copy;
}

static TEST_UNUSED void wordlist_free(WordList *words)
{
    for (size_t i = 0; i < words->count; i++) {
        free(words->items[i]);
    }
    free(words->items);
    words->items = NULL;
    words->count = 0;
}

static int parse_eff_word_line(char *line, char *word, size_t word_size)
{
    char *p = line;
    char *start;
    size_t len;

    while (*p != '\0' && !isspace((unsigned char)*p)) {
        p++;
    }
    while (*p != '\0' && isspace((unsigned char)*p)) {
        p++;
    }
    start = p;
    while (*p != '\0' && !isspace((unsigned char)*p)) {
        p++;
    }
    len = (size_t)(p - start);

    if (len == 0 || len >= word_size) {
        return 0;
    }

    memcpy(word, start, len);
    word[len] = '\0';
    return 1;
}

static TEST_UNUSED int wordlist_load(const char *path, WordList *words, char *err, size_t err_size)
{
    FILE *fp = fopen(path, "r");
    char line[128];
    size_t capacity = EXPECTED_EFF_WORDS;

    words->items = NULL;
    words->count = 0;

    if (fp == NULL) {
        snprintf(err, err_size, "Could not open %s: %s", path, strerror(errno));
        return 0;
    }

    words->items = calloc(capacity, sizeof(*words->items));
    if (words->items == NULL) {
        fclose(fp);
        snprintf(err, err_size, "Out of memory loading wordlist");
        return 0;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        char word[MAX_WORD_LEN];
        if (!parse_eff_word_line(line, word, sizeof(word))) {
            continue;
        }

        if (words->count == capacity) {
            size_t next_capacity = capacity * 2;
            char **next = realloc(words->items, next_capacity * sizeof(*next));
            if (next == NULL) {
                fclose(fp);
                wordlist_free(words);
                snprintf(err, err_size, "Out of memory expanding wordlist");
                return 0;
            }
            words->items = next;
            capacity = next_capacity;
        }

        words->items[words->count] = xstrdup(word);
        if (words->items[words->count] == NULL) {
            fclose(fp);
            wordlist_free(words);
            snprintf(err, err_size, "Out of memory copying word");
            return 0;
        }
        words->count++;
    }

    fclose(fp);

    if (words->count != EXPECTED_EFF_WORDS) {
        snprintf(err, err_size, "Expected %d EFF words, loaded %zu", EXPECTED_EFF_WORDS, words->count);
        wordlist_free(words);
        return 0;
    }

    return 1;
}

static TEST_UNUSED void app_generate(App *app)
{
    int ok;

    if (app->settings.mode == MODE_PASSPHRASE) {
        ok = generate_passphrase(&app->settings, &app->words, app->current, sizeof(app->current));
    } else {
        ok = generate_password(&app->settings, app->current, sizeof(app->current));
    }

    if (ok) {
        history_add(&app->history, app->current);
        snprintf(app->status, sizeof(app->status), "Ready");
    } else {
        snprintf(app->status, sizeof(app->status), "Generation failed; enable at least one character set.");
    }
}

static TEST_UNUSED void copy_current(App *app)
{
    FILE *pipe;
    size_t len = strlen(app->current);

    if (len == 0) {
        snprintf(app->status, sizeof(app->status), "Nothing to copy yet.");
        return;
    }

    pipe = popen("pbcopy", "w");
    if (pipe == NULL) {
        snprintf(app->status, sizeof(app->status), "Could not start pbcopy.");
        return;
    }

    if (fwrite(app->current, 1, len, pipe) != len || pclose(pipe) == -1) {
        snprintf(app->status, sizeof(app->status), "Copy failed.");
        return;
    }

    app->copied_flash = 2;
    snprintf(app->status, sizeof(app->status), "Copied to clipboard with pbcopy.");
}

static void masked_output(const char *input, char *out, size_t out_size)
{
    size_t len = strlen(input);
    size_t count;

    if (out_size == 0) {
        return;
    }

    count = len < out_size - 1 ? len : out_size - 1;
    memset(out, '*', count);
    out[count] = '\0';
}

#ifndef PASSGEN_TEST
static void init_colors(void)
{
    if (!has_colors()) {
        return;
    }
    start_color();
    use_default_colors();
    init_pair(1, COLOR_CYAN, -1);
    init_pair(2, COLOR_GREEN, -1);
    init_pair(3, COLOR_YELLOW, -1);
    init_pair(4, COLOR_RED, -1);
    init_pair(5, COLOR_BLACK, COLOR_GREEN);
    init_pair(6, COLOR_BLACK, COLOR_YELLOW);
    init_pair(7, COLOR_BLACK, COLOR_RED);
    init_pair(8, COLOR_WHITE, COLOR_BLUE);
}

static void box_title(WINDOW *win, const char *title)
{
    int width = getmaxx(win);

    box(win, 0, 0);
    wattron(win, A_BOLD);
    if (width > 6) {
        mvwprintw(win, 0, 2, " %-.*s ", width - 6, title);
    }
    wattroff(win, A_BOLD);
}

static void wadd_clipped(WINDOW *win, int y, int x, int width, const char *text)
{
    if (width <= 0) {
        return;
    }
    mvwaddnstr(win, y, x, text, width);
}

static int wadd_wrapped(WINDOW *win, int y, int x, int width, int max_lines, const char *text)
{
    size_t len = strlen(text);
    size_t offset = 0;
    int line = 0;

    if (width <= 0 || max_lines <= 0) {
        return 0;
    }

    while (offset < len && line < max_lines) {
        size_t remaining = len - offset;
        int chunk = remaining > (size_t)width ? width : (int)remaining;
        mvwaddnstr(win, y + line, x, text + offset, chunk);
        offset += (size_t)chunk;
        line++;
    }

    return line;
}

static const char *toggle_text(int enabled)
{
    return enabled ? "ON " : "OFF";
}

static void draw_toggle(WINDOW *win, int y, int x, const char *key, const char *label, int enabled)
{
    int width = getmaxx(win);

    if (x + 18 >= width) {
        return;
    }

    mvwprintw(win, y, x, "[%s] %-7s ", key, label);
    wattron(win, enabled ? COLOR_PAIR(2) | A_BOLD : COLOR_PAIR(4));
    wprintw(win, "%s", toggle_text(enabled));
    wattroff(win, enabled ? COLOR_PAIR(2) | A_BOLD : COLOR_PAIR(4));
}

static void draw_slider(WINDOW *win, int y, int x, int width, int value)
{
    int bar_width = width - 11;
    int pos;

    if (bar_width < 10) {
        return;
    }

    pos = (value - MIN_LENGTH) * (bar_width - 1) / (MAX_LENGTH - MIN_LENGTH);
    mvwprintw(win, y, x, "%3d ", value);
    for (int i = 0; i < bar_width; i++) {
        int represented = MIN_LENGTH + i * (MAX_LENGTH - MIN_LENGTH) / (bar_width - 1);
        if (i == pos) {
            wattron(win, COLOR_PAIR(8) | A_BOLD);
            waddch(win, ' ');
            wattroff(win, COLOR_PAIR(8) | A_BOLD);
        } else if (represented >= 14) {
            wattron(win, COLOR_PAIR(2));
            waddch(win, ACS_CKBOARD);
            wattroff(win, COLOR_PAIR(2));
        } else {
            waddch(win, ACS_HLINE);
        }
    }
    wprintw(win, " %d", MAX_LENGTH);
}

static void draw_entropy_bar(WINDOW *win, int y, int x, int width, double bits)
{
    int filled;
    int pair = 4;
    int bar_width = width - 9;

    if (bits >= 80.0) {
        pair = 2;
    } else if (bits >= 50.0) {
        pair = 3;
    }

    if (bar_width < 10) {
        return;
    }

    wmove(win, y, x);
    filled = (int)((bits / 128.0) * (double)bar_width);
    if (filled > bar_width) {
        filled = bar_width;
    }
    if (filled < 0) {
        filled = 0;
    }

    waddch(win, '[');
    for (int i = 0; i < bar_width; i++) {
        if (i < filled) {
            wattron(win, COLOR_PAIR(pair) | A_BOLD);
            waddch(win, '#');
            wattroff(win, COLOR_PAIR(pair) | A_BOLD);
        } else {
            waddch(win, '-');
        }
    }
    wprintw(win, "] 128");
}

static void draw_settings(WINDOW *win, const App *app)
{
    int width = getmaxx(win);
    const Settings *s = &app->settings;
    char line[128];

    box_title(win, "Settings");
    mvwprintw(win, 2, 2, "[M] Mode ");
    wattron(win, COLOR_PAIR(1) | A_BOLD);
    wprintw(win, "%s", mode_label(s));
    wattroff(win, COLOR_PAIR(1) | A_BOLD);

    if (s->mode == MODE_PASSPHRASE) {
        mvwprintw(win, 4, 2, "[-/+] Words ");
        wattron(win, COLOR_PAIR(1) | A_BOLD);
        wprintw(win, "%d", passphrase_word_count(s));
        wattroff(win, COLOR_PAIR(1) | A_BOLD);
        mvwprintw(win, 4, 24, "%d..%d", MIN_WORDS, MAX_WORDS);
        mvwprintw(win, 6, 2, "[T] Separator ");
        wattron(win, COLOR_PAIR(1) | A_BOLD);
        wprintw(win, "%s", passphrase_separator_label(s));
        wattroff(win, COLOR_PAIR(1) | A_BOLD);
        snprintf(line, sizeof(line), "%zu words / %.2f bits each",
                 app->words.count, log2((double)app->words.count));
        wadd_clipped(win, 8, 2, width - 4, line);
    } else {
        char pool[128];
        mvwprintw(win, 4, 2, "[-/+] Length");
        draw_slider(win, 4, 17, width - 22, s->length);
        wadd_clipped(win, 5, 17, width - 19, "8+ / 14+");

        draw_toggle(win, 6, 2, "U", "Upper", s->uppercase);
        draw_toggle(win, 6, 24, "L", "Lower", s->lowercase);
        draw_toggle(win, 7, 2, "D", "Digits", s->digits);
        draw_toggle(win, 7, 24, "S", "Symbols", s->symbols);
        snprintf(line, sizeof(line), "Pool: %zu chars", build_pool(s, pool, sizeof(pool)));
        wadd_clipped(win, 8, 2, width - 4, line);
    }
}

static void draw_output(WINDOW *win, const App *app)
{
    int width = getmaxx(win);
    int height = getmaxy(win);
    int pair = app->copied_flash > 0 ? 2 : 1;
    int output_lines = height - 4;
    int used_lines;
    char masked[MAX_OUTPUT];
    const char *shown = app->current;

    if (!app->output_visible) {
        masked_output(app->current, masked, sizeof(masked));
        shown = masked;
    }

    box_title(win, app->output_visible ? "Secret" : "Secret Hidden");
    wattron(win, COLOR_PAIR(pair) | A_BOLD);
    used_lines = wadd_wrapped(win, 2, 2, width - 4, output_lines, shown);
    wattroff(win, COLOR_PAIR(pair) | A_BOLD);
    if (used_lines < 1) {
        used_lines = 1;
    }
    wadd_clipped(win, height - 2, 2, width - 4, app->status);
}

static void draw_entropy(WINDOW *win, const App *app)
{
    int width = getmaxx(win);
    double bits = current_entropy_bits(&app->settings, app->words.count);
    const char *label = entropy_label(bits);
    char line[96];

    box_title(win, "Entropy");
    snprintf(line, sizeof(line), "%.1f bits    %s", bits, label);
    wadd_clipped(win, 2, 2, width - 4, line);
    draw_entropy_bar(win, 4, 2, width - 4, bits);
}

static void draw_history(WINDOW *win, const App *app)
{
    int width = getmaxx(win);
    int height = getmaxy(win);
    size_t rows = height > 4 ? (size_t)(height - 4) : 0;
    size_t visible = history_visible_count(app->history_visibility, app->history.count);
    size_t offset = app->history_visibility == HISTORY_ALL ? app->history_scroll : 0;

    box_title(win, app->history_visibility == HISTORY_LAST ? "Latest" : "History");
    if (app->history_visibility == HISTORY_ALL) {
        char label[96];
        snprintf(label, sizeof(label), "%zu/%zu", visible < rows ? visible : rows, app->history.count);
        wadd_clipped(win, 1, 2, width - 4, label);
    } else {
        wadd_clipped(win, 1, 2, width - 4, "latest");
    }

    if (offset > visible) {
        offset = visible;
    }
    visible -= offset;
    if (visible > rows) {
        visible = rows;
    }

    for (size_t i = 0; i < visible; i++) {
        size_t index = offset + i;
        mvwprintw(win, (int)i + 2, 2, "%3zu ", index + 1);
        wadd_clipped(win, (int)i + 2, 7, width - 9, app->history.items[index]);
    }
}

static void draw_header(const App *app, int cols)
{
    double bits = current_entropy_bits(&app->settings, app->words.count);
    char summary[128];

    attron(A_BOLD | COLOR_PAIR(1));
    mvaddnstr(0, 2, "PwdGen", cols - 4);
    attroff(A_BOLD | COLOR_PAIR(1));
    snprintf(summary, sizeof(summary), "%s | %.1f bits | %s",
             mode_label(&app->settings), bits, entropy_label(bits));
    mvaddnstr(0, cols - (int)strlen(summary) - 2, summary, (int)strlen(summary));
}

static void draw_footer(const App *app, int rows, int cols)
{
    const char *footer = "Space regen  V reveal  C copy  M mode  H history  ? help  Q quit";

    if (app->history_visibility == HISTORY_ALL) {
        footer = "Space regen  V reveal  C copy  Up/Down scroll  PgUp/PgDn page  ? help  Q quit";
    }

    attron(A_REVERSE);
    mvhline(rows - 1, 0, ' ', cols);
    mvaddnstr(rows - 1, 2, footer, cols - 4);
    attroff(A_REVERSE);
}

static void draw_help_overlay(int rows, int cols)
{
    int height = 14;
    int width = 64;
    int y = (rows - height) / 2;
    int x = (cols - width) / 2;
    WINDOW *help;

    if (height > rows - 2 || width > cols - 2) {
        return;
    }

    help = newwin(height, width, y, x);
    box_title(help, "Help");
    mvwprintw(help, 2, 3, "Space/Enter  regenerate");
    mvwprintw(help, 3, 3, "V            reveal / hide secret");
    mvwprintw(help, 4, 3, "C            copy real secret");
    mvwprintw(help, 5, 3, "M            switch mode");
    mvwprintw(help, 6, 3, "-/+          length or words");
    mvwprintw(help, 7, 3, "[/]          fast adjust");
    mvwprintw(help, 8, 3, "U L D S      password character sets");
    mvwprintw(help, 9, 3, "T            passphrase separator");
    mvwprintw(help, 10, 3, "h / H        latest / full history");
    mvwprintw(help, 11, 3, "Up/Down      scroll full history");
    mvwprintw(help, 12, 3, "? or Esc     close help");
    wnoutrefresh(help);
    delwin(help);
}

static void draw_app(const App *app)
{
    int rows;
    int cols;
    int left_w;
    int right_w;
    int settings_h = 9;
    int output_h;
    int entropy_h = 6;
    int show_history = app->history_visibility != HISTORY_HIDDEN;
    WINDOW *settings;
    WINDOW *output;
    WINDOW *entropy;
    WINDOW *history = NULL;

    getmaxyx(stdscr, rows, cols);
    werase(stdscr);

    if (rows < 24 || cols < 78) {
        mvaddnstr(0, 0, "Terminal too small. Please resize to at least 78x24.", cols - 1);
        wnoutrefresh(stdscr);
        doupdate();
        return;
    }

    left_w = show_history ? (cols * 62) / 100 : cols;
    right_w = cols - left_w;

    draw_header(app, cols);

    output_h = rows - 2 - settings_h - entropy_h;
    if (output_h < 7) {
        output_h = 7;
    }

    settings = newwin(settings_h, left_w, 1, 0);
    output = newwin(output_h, left_w, 1 + settings_h, 0);
    entropy = newwin(entropy_h, left_w, 1 + settings_h + output_h, 0);
    if (show_history) {
        history = newwin(rows - 2, right_w, 1, left_w);
    }

    scrollok(stdscr, FALSE);
    scrollok(settings, FALSE);
    scrollok(output, FALSE);
    scrollok(entropy, FALSE);
    if (history != NULL) {
        scrollok(history, FALSE);
    }

    draw_settings(settings, app);
    draw_output(output, app);
    draw_entropy(entropy, app);
    if (history != NULL) {
        draw_history(history, app);
    } else {
    }
    draw_footer(app, rows, cols);

    wnoutrefresh(stdscr);
    wnoutrefresh(settings);
    wnoutrefresh(output);
    wnoutrefresh(entropy);
    if (history != NULL) {
        wnoutrefresh(history);
    }
    if (app->help_visible) {
        draw_help_overlay(rows, cols);
    }
    doupdate();

    delwin(settings);
    delwin(output);
    delwin(entropy);
    if (history != NULL) {
        delwin(history);
    }
}

static void handle_key(App *app, int ch, int *running)
{
    size_t history_view_rows = app->history.count < 10 ? app->history.count : 10;

    if (app->help_visible) {
        if (ch == '?' || ch == 27 || ch == 'q' || ch == 'Q') {
            app->help_visible = 0;
            clearok(curscr, TRUE);
        }
        return;
    }

    switch (ch) {
    case KEY_UP:
        if (app->history_visibility == HISTORY_ALL) {
            history_scroll_by(&app->history_scroll, app->history.count, history_view_rows, -1);
        }
        break;
    case KEY_DOWN:
        if (app->history_visibility == HISTORY_ALL) {
            history_scroll_by(&app->history_scroll, app->history.count, history_view_rows, 1);
        }
        break;
    case KEY_PPAGE:
        if (app->history_visibility == HISTORY_ALL) {
            history_scroll_by(&app->history_scroll, app->history.count, history_view_rows, -10);
        }
        break;
    case KEY_NPAGE:
        if (app->history_visibility == HISTORY_ALL) {
            history_scroll_by(&app->history_scroll, app->history.count, history_view_rows, 10);
        }
        break;
    case KEY_LEFT:
    case '-':
    case '_':
        if (app->settings.mode == MODE_PASSPHRASE) {
            adjust_word_count(&app->settings, -1);
        } else {
            adjust_length(&app->settings, -1);
        }
        app_generate(app);
        break;
    case KEY_RIGHT:
    case '+':
    case '=':
        if (app->settings.mode == MODE_PASSPHRASE) {
            adjust_word_count(&app->settings, 1);
        } else {
            adjust_length(&app->settings, 1);
        }
        app_generate(app);
        break;
    case '[':
    case '{':
        if (app->settings.mode == MODE_PASSPHRASE) {
            adjust_word_count(&app->settings, -2);
        } else {
            adjust_length(&app->settings, -8);
        }
        app_generate(app);
        break;
    case ']':
    case '}':
        if (app->settings.mode == MODE_PASSPHRASE) {
            adjust_word_count(&app->settings, 2);
        } else {
            adjust_length(&app->settings, 8);
        }
        app_generate(app);
        break;
    case 'u':
    case 'U':
        if (app->settings.mode == MODE_PASSWORD) {
            app->settings.uppercase = !app->settings.uppercase;
            app_generate(app);
        }
        break;
    case 'l':
    case 'L':
        if (app->settings.mode == MODE_PASSWORD) {
            app->settings.lowercase = !app->settings.lowercase;
            app_generate(app);
        }
        break;
    case 'd':
    case 'D':
        if (app->settings.mode == MODE_PASSWORD) {
            app->settings.digits = !app->settings.digits;
            app_generate(app);
        }
        break;
    case 's':
    case 'S':
        if (app->settings.mode == MODE_PASSWORD) {
            app->settings.symbols = !app->settings.symbols;
            app_generate(app);
        }
        break;
    case 'm':
    case 'M':
        app->settings.mode = app->settings.mode == MODE_PASSWORD ? MODE_PASSPHRASE : MODE_PASSWORD;
        app_generate(app);
        break;
    case 'c':
    case 'C':
        copy_current(app);
        break;
    case 'v':
    case 'V':
        app->output_visible = !app->output_visible;
        snprintf(app->status, sizeof(app->status), "Output %s",
                 app->output_visible ? "visible" : "hidden");
        break;
    case 't':
    case 'T':
        if (app->settings.mode == MODE_PASSPHRASE) {
            cycle_passphrase_separator(&app->settings);
            app_generate(app);
        }
        break;
    case 'h':
        app->history_visibility = app->history_visibility == HISTORY_LAST ? HISTORY_HIDDEN : HISTORY_LAST;
        break;
    case 'H':
        app->history_visibility = app->history_visibility == HISTORY_ALL ? HISTORY_HIDDEN : HISTORY_ALL;
        app->history_scroll = 0;
        break;
    case '?':
        app->help_visible = 1;
        break;
    case ' ':
    case '\n':
    case '\r':
    case KEY_ENTER:
        app_generate(app);
        break;
    case 'q':
    case 'Q':
    case 27:
        *running = 0;
        break;
    default:
        break;
    }
}

int main(void)
{
    App app;
    int running = 1;
    char err[160];

    memset(&app, 0, sizeof(app));
    app.settings.length = 16;
    app.settings.uppercase = 1;
    app.settings.lowercase = 1;
    app.settings.digits = 1;
    app.settings.symbols = 1;
    app.settings.word_count = 4;
    app.settings.separator_mode = SEPARATOR_HYPHEN;
    app.settings.mode = MODE_PASSWORD;
    app.history_visibility = HISTORY_HIDDEN;

    if (!isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO)) {
        fprintf(stderr, "passgen requires an interactive terminal. Run it directly as `./passgen`.\n");
        return 1;
    }

    if (!wordlist_load("eff_large_wordlist.txt", &app.words, err, sizeof(err))) {
        fprintf(stderr, "%s\nRun `make` to download the EFF large wordlist.\n", err);
        return 1;
    }

    if (!secure_random_bytes(err, 32)) {
        fprintf(stderr, "Warning: getentropy supplement unavailable; continuing with arc4random_buf.\n");
    }

    initscr();
    cbreak();
    noecho();
    nonl();
    keypad(stdscr, TRUE);
    curs_set(0);
    timeout(-1);
    scrollok(stdscr, FALSE);
    init_colors();
    clearok(curscr, TRUE);
    erase();
    refresh();

    app_generate(&app);

    while (running) {
        int ch;
        draw_app(&app);
        if (app.copied_flash > 0) {
            app.copied_flash--;
        }
        ch = getch();
        if (ch == KEY_RESIZE) {
            continue;
        }
        handle_key(&app, ch, &running);
    }

    endwin();
    history_clear(&app.history);
    wordlist_free(&app.words);
    return 0;
}
#else
static int test_entropy(void)
{
    Settings s = {16, 1, 1, 1, 1, 4, SEPARATOR_HYPHEN, MODE_PASSWORD};
    double bits = password_entropy_bits(&s);
    return bits > 102.0 && bits < 104.0;
}

static int test_word_count(void)
{
    Settings s = {16, 1, 1, 1, 1, 4, SEPARATOR_HYPHEN, MODE_PASSPHRASE};
    if (passphrase_word_count(&s) != 4) {
        return 0;
    }
    s.word_count = 1;
    if (passphrase_word_count(&s) != 1) {
        return 0;
    }
    s.word_count = 32;
    return passphrase_word_count(&s) == 32;
}

static int test_wordlist_parse(void)
{
    char line[] = "11111\tabacus\n";
    char word[MAX_WORD_LEN];
    return parse_eff_word_line(line, word, sizeof(word)) && strcmp(word, "abacus") == 0;
}

static int test_generate_password(void)
{
    Settings s = {32, 0, 1, 0, 0, 4, SEPARATOR_HYPHEN, MODE_PASSWORD};
    char out[MAX_OUTPUT];
    if (!generate_password(&s, out, sizeof(out)) || strlen(out) != 32) {
        return 0;
    }
    for (size_t i = 0; out[i] != '\0'; i++) {
        if (out[i] < 'a' || out[i] > 'z') {
            return 0;
        }
    }
    return 1;
}

static int test_adjust_length(void)
{
    Settings s = {16, 1, 1, 1, 1, 4, SEPARATOR_HYPHEN, MODE_PASSWORD};
    adjust_length(&s, -20);
    if (s.length != MIN_LENGTH) {
        return 0;
    }
    adjust_length(&s, 500);
    if (s.length != MAX_LENGTH) {
        return 0;
    }
    adjust_length(&s, -8);
    return s.length == MAX_LENGTH - 8;
}

static int test_generate_one_character_password(void)
{
    Settings s = {1, 0, 1, 0, 0, 4, SEPARATOR_HYPHEN, MODE_PASSWORD};
    char out[MAX_OUTPUT];
    return generate_password(&s, out, sizeof(out)) && strlen(out) == 1;
}

static int test_adjust_words(void)
{
    Settings s = {16, 1, 1, 1, 1, 6, SEPARATOR_HYPHEN, MODE_PASSPHRASE};
    adjust_word_count(&s, -20);
    if (s.word_count != MIN_WORDS) {
        return 0;
    }
    adjust_word_count(&s, 99);
    if (s.word_count != MAX_WORDS) {
        return 0;
    }
    adjust_word_count(&s, -2);
    return s.word_count == MAX_WORDS - 2;
}

static int test_passphrase_separator(void)
{
    Settings s = {16, 1, 1, 1, 1, 4, SEPARATOR_HYPHEN, MODE_PASSPHRASE};
    if (passphrase_separator(&s) != '-') {
        return 0;
    }
    cycle_passphrase_separator(&s);
    if (passphrase_separator(&s) != ' ') {
        return 0;
    }
    cycle_passphrase_separator(&s);
    if (passphrase_separator(&s) != '\0') {
        return 0;
    }
    cycle_passphrase_separator(&s);
    return passphrase_separator(&s) == '-';
}

static int test_masked_output(void)
{
    char out[16];
    masked_output("secret words", out, sizeof(out));
    if (strcmp(out, "************") != 0) {
        return 0;
    }
    masked_output("abcdef", out, 4);
    return strcmp(out, "***") == 0;
}

static int test_history_visibility(void)
{
    if (history_visible_count(HISTORY_HIDDEN, 10) != 0) {
        return 0;
    }
    if (history_visible_count(HISTORY_LAST, 10) != 1) {
        return 0;
    }
    if (history_visible_count(HISTORY_LAST, 0) != 0) {
        return 0;
    }
    return history_visible_count(HISTORY_ALL, 10) == 10;
}

static int test_history_capacity_and_scroll(void)
{
    History history;
    size_t offset = 0;

    memset(&history, 0, sizeof(history));
    for (int i = 0; i < 105; i++) {
        char item[16];
        snprintf(item, sizeof(item), "item-%d", i);
        history_add(&history, item);
    }

    if (history.count != HISTORY_MAX || strcmp(history.items[0], "item-104") != 0) {
        history_clear(&history);
        return 0;
    }

    history_scroll_by(&offset, history.count, 10, 50);
    if (offset != 50) {
        history_clear(&history);
        return 0;
    }
    history_scroll_by(&offset, history.count, 10, 999);
    if (offset != 90) {
        history_clear(&history);
        return 0;
    }
    history_scroll_by(&offset, history.count, 10, -999);
    if (offset != 0) {
        history_clear(&history);
        return 0;
    }

    history_clear(&history);
    return 1;
}

int main(void)
{
    if (!test_entropy()) {
        fprintf(stderr, "test_entropy failed\n");
        return 1;
    }
    if (!test_word_count()) {
        fprintf(stderr, "test_word_count failed\n");
        return 1;
    }
    if (!test_wordlist_parse()) {
        fprintf(stderr, "test_wordlist_parse failed\n");
        return 1;
    }
    if (!test_generate_password()) {
        fprintf(stderr, "test_generate_password failed\n");
        return 1;
    }
    if (!test_adjust_length()) {
        fprintf(stderr, "test_adjust_length failed\n");
        return 1;
    }
    if (!test_generate_one_character_password()) {
        fprintf(stderr, "test_generate_one_character_password failed\n");
        return 1;
    }
    if (!test_adjust_words()) {
        fprintf(stderr, "test_adjust_words failed\n");
        return 1;
    }
    if (!test_passphrase_separator()) {
        fprintf(stderr, "test_passphrase_separator failed\n");
        return 1;
    }
    if (!test_masked_output()) {
        fprintf(stderr, "test_masked_output failed\n");
        return 1;
    }
    if (!test_history_visibility()) {
        fprintf(stderr, "test_history_visibility failed\n");
        return 1;
    }
    if (!test_history_capacity_and_scroll()) {
        fprintf(stderr, "test_history_capacity_and_scroll failed\n");
        return 1;
    }
    puts("passgen tests passed");
    return 0;
}
#endif

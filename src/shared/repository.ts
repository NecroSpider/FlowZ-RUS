/**
 * 本发行版的 GitHub 仓库单一真值：应用自更新（releases API + 下载）、托盘「打开 releases」、关于页仓库链接与
 * 「报告问题」均派生自此。fork 发行改这里即可，避免漏改某处致更新仍拉上游 release、覆盖本 fork 的修复。
 */
export const GITHUB_OWNER = 'NecroSpider';
export const GITHUB_REPO = 'FlowZ-RUS';
export const REPOSITORY_URL = `https://github.com/${GITHUB_OWNER}/${GITHUB_REPO}`;
export const RELEASES_URL = `${REPOSITORY_URL}/releases`;

/** 本 fork 作者的 Telegram（关于页按钮）。 */
export const AUTHOR_TELEGRAM_URL = 'https://t.me/necro_spider';
/** 本 fork 所基于的原版 FlowZ（关于页「原版 FlowZ」按钮）。 */
export const UPSTREAM_REPOSITORY_URL = 'https://github.com/dododook/FlowZ';

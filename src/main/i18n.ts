/**
 * 主进程用户可见文案的轻量 i18n（与渲染端 SUPPORTED_LANGUAGES 对齐：en-US / ru / fa）。
 *
 * 背景：渲染端用 i18next（locales/*.json）做 5 语，但**主进程没有 i18next 实例**。历史上主进程用户串走
 * 「zh/en 二元」土办法（TrayManager.t / native dialog），fa/ru/zh-TW 用户看到英文，部分串甚至纯中文。
 * 本模块给主进程一个真 5 语出口：中央语言持有点 + 文案目录，桌面通知/托盘/对话框等调 mt() 即可。
 *
 * 设计：
 * - 文案主进程私有（渲染端从不显示这些串，故不复用 renderer 的 locale JSON——且 tsconfig.main 也 import 不到它）。
 * - 语言持有点据 config.language 单一真值源写入：index.ts 在启动读 config + config-change 变更时 setMainLanguage。
 * - 缺键/未知语言 → 回退 DEFAULT_LANGUAGE，绝不抛。
 * - MESSAGES 用 `satisfies Record<string, Record<SupportedLanguage,string>>`：编译期强制每键各语齐全，
 *   且 `MainMessageKey = keyof typeof MESSAGES` 自动派生 key 联合类型（新增键无需手维护 union）。
 */
import {
  DEFAULT_LANGUAGE,
  resolveEffectiveLanguage,
  type SupportedLanguage,
} from '../shared/language';

/** key → 各受支持语言文案。satisfies 保证每键各语齐全；新增主进程用户可见串在此扩展。 */
const MESSAGES = {
  // —— CLI / 非 GUI 早退（cli-early-exit，main 进程顶层；headless 提示走系统 locale，禁硬编码） ——
  headlessNoDisplay: {
    'en-US':
      'FlowZ is a GUI application and needs a desktop environment; no display server (DISPLAY/Wayland) was detected. To check the version, run: flowz --version',
    ru: 'FlowZ — графическое приложение, которому нужна среда рабочего стола; сервер отображения (DISPLAY/Wayland) не обнаружен. Чтобы узнать версию, выполните: flowz --version',
    fa: 'FlowZ یک برنامهٔ گرافیکی است و به محیط دسکتاپ نیاز دارد؛ هیچ سرور نمایشی (DISPLAY/Wayland) شناسایی نشد. برای دیدن نسخه اجرا کنید: flowz --version',
  },
  // —— 本地导入文件对话框（subscription-handlers，dialog.showOpenDialog title/filters 跟随系统语言） ——
  localImportPickTitle: {
    'en-US': 'Select Config File',
    ru: 'Выберите файл конфигурации',
    fa: 'انتخاب فایل پیکربندی',
  },
  localImportFilterConfig: {
    'en-US': 'Config files',
    ru: 'Файлы конфигурации',
    fa: 'فایل‌های پیکربندی',
  },
  localImportFilterAll: {
    'en-US': 'All files',
    ru: 'Все файлы',
    fa: 'همه فایل‌ها',
  },
  // —— Windows 便携自更新覆盖失败提示（update-install-script VBS MsgBox；路径由 VBS 拼接，故末尾留冒号） ——
  portableUpdateManualReplace: {
    'en-US':
      'FlowZ auto-update could not replace the portable executable. The new version was downloaded to the path below — please replace it manually:',
    ru: 'FlowZ не смог заменить переносимый файл при автообновлении. Новая версия загружена по пути ниже — замените её вручную:',
    fa: 'به‌روزرسانی خودکار FlowZ نتوانست فایل قابل‌حمل را جایگزین کند. نسخهٔ جدید در مسیر زیر دانلود شد — لطفاً به‌صورت دستی جایگزین کنید:',
  },
  // —— deb 更新的一次性授权说明（pkexec polkit 通用框文案改不了，先在 app 内解释缘由） ——
  debUpdateElevationTitle: {
    'en-US': 'Update needs a one-time administrator authorization',
    ru: 'Для обновления нужна однократная авторизация администратора',
    fa: 'به‌روزرسانی به یک مجوز مدیر (یک‌بار) نیاز دارد',
  },
  debUpdateElevationMessage: {
    'en-US': 'About to update FlowZ (deb build)',
    ru: 'Обновление FlowZ (сборка deb)',
    fa: 'در حال به‌روزرسانی FlowZ (نسخهٔ deb)',
  },
  debUpdateElevationDetail: {
    'en-US':
      'The deb build is installed under the system directory /opt, and installing software itself requires administrator rights, so the system will show an authorization prompt once. This is separate from running the proxy / using TUN password-free — the privileged helper is a one-time install and then stays password-free; app updates need one authorization each time (not each use). For fully authorization-free updates, switch to the AppImage build.',
    ru: 'Сборка deb установлена в системный каталог /opt, а установка ПО требует прав администратора, поэтому система один раз покажет запрос авторизации. Это не связано с беспарольным запуском прокси / использованием TUN — привилегированный помощник ставится один раз и далее работает без пароля; обновления приложения требуют по одной авторизации каждый раз (не при каждом использовании). Для полностью беспарольных обновлений перейдите на сборку AppImage.',
    fa: 'نسخهٔ deb در مسیر سیستمی ‎/opt نصب می‌شود و نصب نرم‌افزار به دسترسی مدیر نیاز دارد، پس سیستم یک بار پنجرهٔ مجوز را نشان می‌دهد. این جدا از اجرای بدون‌رمز پروکسی / استفاده از TUN است — دستیار پرمجوز یک‌بار نصب می‌شود و سپس بدون رمز کار می‌کند؛ اما به‌روزرسانی برنامه هر بار به یک مجوز نیاز دارد (نه در هر بار استفاده). برای به‌روزرسانی کاملاً بدون مجوز، به نسخهٔ AppImage تغییر دهید.',
  },
  debUpdateElevationContinue: {
    'en-US': 'Continue',
    ru: 'Продолжить',
    fa: 'ادامه',
  },
  debUpdateElevationCancel: {
    'en-US': 'Cancel',
    ru: 'Отмена',
    fa: 'لغو',
  },
  // —— 桌面通知（notify-user 出口） ——
  proxyErrorTitle: {
    'en-US': 'FlowZ Proxy Error',
    ru: 'Ошибка прокси FlowZ',
    fa: 'خطای پروکسی FlowZ',
  },
  proxyErrorBody: {
    'en-US': 'The proxy has stopped. Open FlowZ for details.',
    ru: 'Прокси остановлен. Откройте FlowZ, чтобы узнать подробности.',
    fa: 'پروکسی متوقف شد. برای جزئیات FlowZ را باز کنید.',
  },
  fakeIpTunAutoEnabledTitle: {
    'en-US': 'FakeIP enabled automatically',
    ru: 'FakeIP включён автоматически',
    fa: 'FakeIP به‌طور خودکار فعال شد',
  },
  fakeIpTunAutoEnabledBody: {
    'en-US':
      'FakeIP was enabled automatically for TUN mode (recommended). Turn it off in Settings → Network.',
    ru: 'FakeIP включён автоматически для режима TUN (рекомендуется). Отключить можно в «Настройки → Сеть».',
    fa: 'FakeIP برای حالت TUN به‌طور خودکار فعال شد (توصیه‌شده). در تنظیمات ← شبکه خاموش کنید.',
  },
  helperDisabledTitle: {
    'en-US': 'FlowZ helper disabled',
    ru: 'Помощник FlowZ отключён',
    fa: 'دستیار FlowZ غیرفعال شد',
  },
  helperDisabledBody: {
    'en-US': "TUN can't auto-start. Click to open settings and re-enable.",
    ru: 'TUN не запускается автоматически. Нажмите, чтобы открыть настройки.',
    fa: 'TUN به‌طور خودکار اجرا نمی‌شود. برای باز کردن تنظیمات کلیک کنید.',
  },
  tailscaleAuthBody: {
    'en-US': 'Complete sign-in in your browser to join the network',
    ru: 'Завершите вход в браузере, чтобы присоединиться к сети',
    fa: 'برای پیوستن به شبکه، ورود را در مرورگر کامل کنید',
  },

  // —— 完全卸载（Linux 本体删不掉时引导手动移除：deb 系统装 root 无权 / 无废纸篓后端 / 边缘形态） ——
  uninstallManualTitle: {
    'en-US': 'Remove the app manually',
    ru: 'Удалите приложение вручную',
    fa: 'برنامه را به‌صورت دستی حذف کنید',
  },
  uninstallManualMessage: {
    'en-US': 'FlowZ user data has been removed.',
    ru: 'Пользовательские данные FlowZ удалены.',
    fa: 'داده‌های کاربری FlowZ حذف شد.',
  },
  // detail 末尾会拼接应用本体的实际路径（exe 目录或 AppImage 文件），故以冒号结尾。
  uninstallManualBody: {
    'en-US':
      'The app itself could not be removed automatically (it may be in a system or protected location):\n• If installed via .deb: sudo apt remove flowz (or sudo dpkg -r flowz)\n• If running as an AppImage: delete your .AppImage file\n• Otherwise, delete this path manually:',
    ru: 'Само приложение не удалось удалить автоматически (возможно, оно в системном или защищённом расположении):\n• Если установлено через .deb: sudo apt remove flowz (или sudo dpkg -r flowz)\n• Если запущено как AppImage: удалите ваш файл .AppImage\n• Иначе удалите этот путь вручную:',
    fa: 'خودِ برنامه به‌صورت خودکار حذف نشد (ممکن است در مسیری سیستمی یا محافظت‌شده باشد):\n• اگر از طریق ‎.deb‎ نصب شده: sudo apt remove flowz (یا sudo dpkg -r flowz)\n• اگر به‌صورت AppImage اجرا می‌شود: فایل ‎.AppImage‎ خود را حذف کنید\n• در غیر این صورت این مسیر را به‌صورت دستی حذف کنید:',
  },
  uninstallManualOk: {
    'en-US': 'Got it',
    ru: 'Понятно',
    fa: 'متوجه شدم',
  },
  // Windows 便携版本体（exe）跨磁盘卷时无法自动移除（同卷靠 move/rename 移出，跨卷退化为复制+删源、删源撞运行锁失败）。
  // detail 末尾拼接本体实际路径，故以冒号结尾。
  uninstallPortableBody: {
    'en-US':
      'The portable program may not be removed automatically when it resides on a different drive. If the location below still exists after uninstall, please delete it manually:',
    ru: 'Переносимая программа может не удалиться автоматически, если она находится на другом диске. Если указанное ниже расположение сохранится после удаления, удалите его вручную:',
    fa: 'برنامهٔ قابل‌حمل ممکن است هنگام قرار داشتن روی درایوی دیگر به‌صورت خودکار حذف نشود. اگر مسیر زیر پس از حذف نصب همچنان باقی ماند، آن را به‌صورت دستی حذف کنید:',
  },

  // —— 托盘菜单（TrayManager） ——
  trayStatusError: {
    'en-US': 'Connection Error',
    ru: 'Ошибка подключения',
    fa: 'خطای اتصال',
  },
  trayStatusConnected: {
    'en-US': 'Connected',
    ru: 'Подключено',
    fa: 'متصل',
  },
  trayStatusDisconnected: {
    'en-US': 'Disconnected',
    ru: 'Отключено',
    fa: 'قطع شد',
  },
  trayTimeout: {
    'en-US': 'Timeout',
    ru: 'Таймаут',
    fa: 'فرصت تمام شد',
  },
  trayDirect: {
    'en-US': 'Direct',
    ru: 'Напрямую',
    fa: 'مستقیم',
  },
  trayNoServers: {
    'en-US': 'No Servers Configured',
    ru: 'Серверы не настроены',
    fa: 'هیچ سروری پیکربندی نشده',
  },
  trayMesh: {
    'en-US': 'Mesh',
    ru: 'Меш-сеть',
    fa: 'شبکه مش',
  },
  trayCustomNodes: {
    'en-US': 'Custom Nodes',
    ru: 'Свои узлы',
    fa: 'گره‌های سفارشی',
  },
  trayManageServers: {
    'en-US': 'Manage Servers',
    ru: 'Управление серверами',
    fa: 'مدیریت سرورها',
  },
  trayGlobalProxy: {
    'en-US': 'Global Proxy',
    ru: 'Глобальный прокси',
    fa: 'پروکسی سراسری',
  },
  traySmartRouting: {
    'en-US': 'Smart Routing',
    ru: 'Умная маршрутизация',
    fa: 'مسیریابی هوشمند',
  },
  trayDirectMode: {
    'en-US': 'Direct Connection',
    ru: 'Прямое подключение',
    fa: 'اتصال مستقیم',
  },
  traySystemProxy: {
    'en-US': 'System Proxy',
    ru: 'Системный прокси',
    fa: 'پروکسی سیستم',
  },
  trayTun: {
    'en-US': 'TUN',
    ru: 'TUN',
    fa: 'TUN',
  },
  trayLocalOnly: {
    'en-US': 'Local Only',
    ru: 'Только локально',
    fa: 'فقط محلی',
  },
  trayOpenMainWindow: {
    'en-US': 'Open Main Window',
    ru: 'Открыть главное окно',
    fa: 'باز کردن پنجره اصلی',
  },
  trayDisableProxy: {
    'en-US': 'Disable Proxy',
    ru: 'Отключить прокси',
    fa: 'غیرفعال‌سازی پروکسی',
  },
  trayEnableProxy: {
    'en-US': 'Enable Proxy',
    ru: 'Включить прокси',
    fa: 'فعال‌سازی پروکسی',
  },
  traySelectServer: {
    'en-US': 'Select Server',
    ru: 'Выбрать сервер',
    fa: 'انتخاب سرور',
  },
  trayTakeover: {
    'en-US': 'Takeover',
    ru: 'Перехват',
    fa: 'نحوه تصاحب',
  },
  trayRouting: {
    'en-US': 'Routing',
    ru: 'Маршрутизация',
    fa: 'مسیریابی',
  },
  trayLightweightMode: {
    'en-US': 'Enter Lightweight Mode',
    ru: 'Лёгкий режим',
    fa: 'حالت سبک',
  },
  trayPrivacyMode: {
    'en-US': 'Enter Privacy Mode',
    ru: 'Режим конфиденциальности',
    fa: 'حالت حریم خصوصی',
  },
  trayOpenSettings: {
    'en-US': 'Open Settings',
    ru: 'Открыть настройки',
    fa: 'باز کردن تنظیمات',
  },
  trayCheckUpdates: {
    'en-US': 'Check for Updates',
    ru: 'Проверить обновления',
    fa: 'بررسی به‌روزرسانی',
  },
  trayQuit: {
    'en-US': 'Quit',
    ru: 'Выход',
    fa: 'خروج',
  },
  trayTestingSpeed: {
    'en-US': 'Testing Speed...',
    ru: 'Проверка скорости...',
    fa: 'در حال تست سرعت...',
  },
  traySpeedTest: {
    'en-US': 'Speed Test',
    ru: 'Тест скорости',
    fa: 'تست سرعت',
  },
  trayTooltipDisconnected: {
    'en-US': 'FlowZ - Disconnected',
    ru: 'FlowZ — Отключено',
    fa: 'FlowZ — قطع شد',
  },
  trayTooltipConnecting: {
    'en-US': 'FlowZ - Connecting...',
    ru: 'FlowZ — Подключение...',
    fa: 'FlowZ — در حال اتصال...',
  },
  trayTooltipConnected: {
    'en-US': 'FlowZ - Connected',
    ru: 'FlowZ — Подключено',
    fa: 'FlowZ — متصل',
  },
  trayNoUpdateBody: {
    'en-US': "You're on the latest version",
    ru: 'У вас установлена последняя версия',
    fa: 'شما از آخرین نسخه استفاده می‌کنید',
  },
  trayNoUpdateOk: {
    'en-US': 'OK',
    ru: 'ОК',
    fa: 'تأیید',
  },

  // —— 提权 helper 授权对话框（index.ts）：按钮 ——
  btnCancel: {
    'en-US': 'Cancel',
    ru: 'Отмена',
    fa: 'لغو',
  },
  btnRepairStart: {
    'en-US': 'Repair & start',
    ru: 'Исправить и запустить',
    fa: 'تعمیر و راه‌اندازی',
  },
  btnInstallStart: {
    'en-US': 'Install & start',
    ru: 'Установить и запустить',
    fa: 'نصب و راه‌اندازی',
  },
  btnUseUac: {
    'en-US': 'Use UAC',
    ru: 'Запустить через UAC',
    fa: 'راه‌اندازی با UAC',
  },
  btnUseSystemAuth: {
    'en-US': 'Use system auth',
    ru: 'С системной авторизацией',
    fa: 'با احراز هویت سیستم',
  },
  btnOpenSystemSettings: {
    'en-US': 'Open System Settings',
    ru: 'Открыть системные настройки',
    fa: 'باز کردن تنظیمات سیستم',
  },
  btnStartThisSession: {
    'en-US': 'Start this session',
    ru: 'Запустить сейчас',
    fa: 'راه‌اندازی این بار',
  },

  // —— 对话框：标题 ——
  dlgWinRepairServiceMsg: {
    'en-US': 'Repair privileged service?',
    ru: 'Исправить привилегированную службу?',
    fa: 'سرویس ممتاز تعمیر شود؟',
  },
  dlgWinInstallServiceMsg: {
    'en-US': 'Install privileged service?',
    ru: 'Установить привилегированную службу?',
    fa: 'سرویس ممتاز نصب شود؟',
  },
  dlgWinHelperInstallFailedMsg: {
    'en-US': 'Failed to install privileged service',
    ru: 'Не удалось установить привилегированную службу',
    fa: 'نصب سرویس ممتاز ناموفق بود',
  },
  dlgHelperInstallFailedMsg: {
    'en-US': 'Failed to install privileged helper',
    ru: 'Не удалось установить привилегированный помощник',
    fa: 'نصب دستیار ممتاز ناموفق بود',
  },
  dlgMacBgOffMsg: {
    'en-US': 'Helper "Allow in Background" is off',
    ru: 'У помощника отключено «Разрешить в фоне»',
    fa: 'گزینه «اجازه در پس‌زمینه» دستیار خاموش است',
  },
  dlgMacRepairHelperMsg: {
    'en-US': 'Repair privileged helper?',
    ru: 'Исправить привилегированный помощник?',
    fa: 'دستیار ممتاز تعمیر شود؟',
  },
  dlgMacInstallHelperMsg: {
    'en-US': 'Install privileged helper?',
    ru: 'Установить привилегированный помощник?',
    fa: 'دستیار ممتاز نصب شود؟',
  },

  // —— 对话框：详情（长段落） ——
  dlgWinRepairDetail: {
    'en-US':
      'The privileged service is installed but not ready. Repair reinstalls it (one UAC prompt); or start with UAC this time.',
    ru: 'Привилегированная служба установлена, но не готова. Восстановление переустановит её (один запрос UAC); либо запустите через UAC сейчас.',
    fa: 'سرویس ممتاز نصب شده اما آماده نیست. تعمیر آن را دوباره نصب می‌کند (یک بار درخواست UAC)؛ یا این بار با UAC راه‌اندازی کنید.',
  },
  dlgWinInstallDetail: {
    'en-US':
      'After install, Windows TUN start/stop no longer needs UAC each time (installing the service needs one admin prompt); or start with UAC this time.',
    ru: 'После установки запуск/остановка TUN в Windows больше не требует UAC каждый раз (установка службы требует одного запроса администратора); либо запустите через UAC сейчас.',
    fa: 'پس از نصب، شروع/توقف TUN در ویندوز دیگر هر بار به UAC نیاز ندارد (نصب سرویس یک بار درخواست مدیر دارد)؛ یا این بار با UAC راه‌اندازی کنید.',
  },
  dlgWinHelperInstallFailedDetail: {
    'en-US': 'This start will use UAC instead. See the app log for details.',
    ru: 'Этот запуск пройдёт через UAC. Подробности — в журнале приложения.',
    fa: 'این بار با UAC راه‌اندازی می‌شود. جزئیات را در گزارش برنامه ببینید.',
  },
  dlgHelperInstallFailedDetail: {
    'en-US':
      'This start will ask for your administrator password instead. See the app log for details.',
    ru: 'Этот запуск запросит пароль администратора. Подробности — в журнале приложения.',
    fa: 'این بار برای راه‌اندازی رمز مدیر درخواست می‌شود. جزئیات را در گزارش برنامه ببینید.',
  },
  dlgLinuxInstallServiceMsg: {
    'en-US': 'Install privileged helper?',
    ru: 'Установить привилегированный помощник?',
    fa: 'دستیار ممتاز نصب شود؟',
  },
  dlgLinuxRepairServiceMsg: {
    'en-US': 'Repair privileged helper?',
    ru: 'Восстановить привилегированный помощник?',
    fa: 'دستیار ممتاز تعمیر شود؟',
  },
  dlgLinuxInstallDetail: {
    'en-US':
      'After install, Linux TUN start/stop no longer prompts each time (installing the systemd service needs one authorization); or start with system auth this time.',
    ru: 'После установки запуск/остановка TUN в Linux больше не запрашивает пароль каждый раз (установка службы systemd требует одной авторизации); либо запустите с системной авторизацией сейчас.',
    fa: 'پس از نصب، شروع/توقف TUN در لینوکس دیگر هر بار درخواست نمی‌کند (نصب سرویس systemd یک بار احراز هویت لازم دارد)؛ یا این بار با احراز هویت سیستم راه‌اندازی کنید.',
  },
  dlgLinuxRepairDetail: {
    'en-US':
      'The privileged helper is installed but not ready (service not running or version mismatch). Repair reinstalls it (one authorization); or start with system auth this time.',
    ru: 'Привилегированный помощник установлен, но не готов (служба не запущена или несовпадение версии). Восстановление переустановит его (одна авторизация); либо запустите с системной авторизацией сейчас.',
    fa: 'دستیار ممتاز نصب شده اما آماده نیست (سرویس در حال اجرا نیست یا نسخه ناسازگار است). تعمیر آن را دوباره نصب می‌کند (یک بار احراز هویت)؛ یا این بار با احراز هویت سیستم راه‌اندازی کنید.',
  },
  dlgMacBgOffDetail: {
    'en-US':
      'Open System Settings → General → Login Items & Extensions and turn the "Allow in Background" toggle back on for FlowZ, then return to FlowZ and start again (no authorization needed then).\n"Start this session" runs with system administrator authorization (one password prompt) and does not depend on the toggle; each start/stop will prompt afterwards, so re-enabling the toggle is recommended.',
    ru: 'Откройте «Системные настройки → Основные → Объекты входа и расширения» и снова включите переключатель «Разрешить в фоне» для FlowZ, затем вернитесь в FlowZ и запустите снова (тогда авторизация не нужна).\n«Запустить сейчас» работает с авторизацией системного администратора (один запрос пароля) и не зависит от переключателя; после этого каждый запуск/остановка будет запрашивать пароль, поэтому рекомендуется снова включить переключатель.',
    fa: 'به «تنظیمات سیستم ← عمومی ← موارد ورود و افزونه‌ها» بروید و کلید «اجازه در پس‌زمینه» را برای FlowZ دوباره روشن کنید، سپس به FlowZ بازگردید و دوباره راه‌اندازی کنید (آنگاه به احراز هویت نیازی نیست).\n«راه‌اندازی این بار» با احراز هویت مدیر سیستم اجرا می‌شود (یک بار درخواست رمز) و به این کلید وابسته نیست؛ اما پس از آن هر شروع/توقف درخواست رمز می‌کند، بنابراین روشن کردن دوباره کلید توصیه می‌شود.',
  },
  dlgMacRepairNoteOff: {
    'en-US':
      '\nNote: if the "Allow in Background" toggle was turned off in System Settings, this repair will NOT restore it; re-enable it manually under System Settings → General → Login Items & Extensions.',
    ru: '\nПримечание: если переключатель «Разрешить в фоне» был выключен в системных настройках, это восстановление НЕ включит его; включите его вручную в «Системные настройки → Основные → Объекты входа и расширения».',
    fa: '\nتوجه: اگر کلید «اجازه در پس‌زمینه» در تنظیمات سیستم خاموش شده باشد، این تعمیر آن را بازنمی‌گرداند؛ آن را به‌صورت دستی در «تنظیمات سیستم ← عمومی ← موارد ورود و افزونه‌ها» دوباره فعال کنید.',
  },
  dlgMacRepairPathMismatchDetail: {
    'en-US':
      'The app was moved and the helper still points to the old path. Repair re-registers the current path (one authorization); or start with system auth this time.',
    ru: 'Приложение было перемещено, а помощник всё ещё указывает на старый путь. Восстановление заново зарегистрирует текущий путь (одна авторизация); либо запустите с системной авторизацией сейчас.',
    fa: 'برنامه جابه‌جا شده و دستیار هنوز به مسیر قدیمی اشاره می‌کند. تعمیر مسیر فعلی را دوباره ثبت می‌کند (یک بار احراز هویت)؛ یا این بار با احراز هویت سیستم راه‌اندازی کنید.',
  },
  dlgMacRepairUpgradeDetail: {
    'en-US':
      'The privileged helper needs updating to a newer version. Repair reinstalls it (one authorization); or start with system auth this time.',
    ru: 'Привилегированный помощник нужно обновить до новой версии. Восстановление переустановит его (одна авторизация); либо запустите с системной авторизацией сейчас.',
    fa: 'دستیار ممتاز باید به نسخه جدیدتری به‌روزرسانی شود. تعمیر آن را دوباره نصب می‌کند (یک بار احراز هویت)؛ یا این بار با احراز هویت سیستم راه‌اندازی کنید.',
  },
  dlgMacInstallDetail: {
    'en-US':
      'After install, TUN start/stop no longer needs system authorization each time; or start with system auth this time.',
    ru: 'После установки запуск/остановка TUN больше не требует системной авторизации каждый раз; либо запустите с системной авторизацией сейчас.',
    fa: 'پس از نصب، شروع/توقف TUN دیگر هر بار به احراز هویت سیستم نیاز ندارد؛ یا این بار با احراز هویت سیستم راه‌اندازی کنید.',
  },

  // —— App 更新弹窗（独立 mini 更新窗，UpdateService.createUpdatePopup；四态标题/文案/按钮） ——
  updRemindTitle: {
    'en-US': 'New version available',
    ru: 'Доступна новая версия',
    fa: 'نسخهٔ جدید موجود است',
  },
  updProgressTitle: {
    'en-US': 'Downloading update',
    ru: 'Загрузка обновления',
    fa: 'در حال دانلود به‌روزرسانی',
  },
  updDoneTitle: {
    'en-US': 'Download complete',
    ru: 'Загрузка завершена',
    fa: 'دانلود کامل شد',
  },
  updErrorTitle: {
    'en-US': 'Download failed',
    ru: 'Ошибка загрузки',
    fa: 'دانلود ناموفق بود',
  },
  updCurrentPrefix: {
    'en-US': 'Current',
    ru: 'Текущая',
    fa: 'فعلی',
  },
  updInstalling: {
    'en-US': 'Downloaded, installing…',
    ru: 'Загружено, установка…',
    fa: 'دانلود شد، در حال نصب…',
  },
  updTryingMirror: {
    'en-US': 'Trying mirror…',
    ru: 'Попытка через зеркало…',
    fa: 'تلاش از طریق سرور آینه…',
  },
  updBtnUpdate: {
    'en-US': 'Update now',
    ru: 'Обновить',
    fa: 'به‌روزرسانی',
  },
  updBtnLater: {
    'en-US': 'Later',
    ru: 'Позже',
    fa: 'بعداً',
  },
  updBtnSkip: {
    'en-US': 'Skip this version',
    ru: 'Пропустить версию',
    fa: 'رد این نسخه',
  },
  updBtnViewLog: {
    'en-US': 'Release notes',
    ru: 'Список изменений',
    fa: 'یادداشت‌های انتشار',
  },
  updBtnCancel: {
    'en-US': 'Cancel download',
    ru: 'Отменить загрузку',
    fa: 'لغو دانلود',
  },
  updBtnRetry: {
    'en-US': 'Retry',
    ru: 'Повторить',
    fa: 'تلاش مجدد',
  },
  updBtnManualDownload: {
    'en-US': 'Download manually',
    ru: 'Скачать вручную',
    fa: 'دانلود دستی',
  },
  updBtnClose: {
    'en-US': 'Close',
    ru: 'Закрыть',
    fa: 'بستن',
  },
  updErrNetwork: {
    'en-US': 'Network interrupted or timed out. Check your connection and retry.',
    ru: 'Сеть прервана или истекло время ожидания. Проверьте подключение и повторите.',
    fa: 'اتصال شبکه قطع شد یا زمان آن به پایان رسید. اتصال را بررسی و دوباره تلاش کنید.',
  },
  updErrIncomplete: {
    'en-US': 'The downloaded file is incomplete. Please retry.',
    ru: 'Загруженный файл неполный. Повторите попытку.',
    fa: 'فایل دانلود‌شده ناقص است. لطفاً دوباره تلاش کنید.',
  },
  updErrIntegrity: {
    'en-US':
      'The installer failed verification (does not match the official release) and was not installed. Retry or download it manually from GitHub.',
    ru: 'Установщик не прошёл проверку (не совпадает с официальным релизом) и не был установлен. Повторите попытку или скачайте вручную с GitHub.',
    fa: 'فایل نصب از بررسی صحت رد شد (با نسخهٔ رسمی مطابقت ندارد) و نصب نشد. دوباره تلاش کنید یا آن را دستی از GitHub دانلود کنید.',
  },
  updErrServer: {
    'en-US': 'The download server returned an error. Please try again later.',
    ru: 'Сервер загрузки вернул ошибку. Повторите попытку позже.',
    fa: 'سرور دانلود خطا برگرداند. لطفاً بعداً دوباره تلاش کنید.',
  },
  updErrGeneric: {
    'en-US': 'Download failed. Please retry.',
    ru: 'Ошибка загрузки. Повторите попытку.',
    fa: 'دانلود ناموفق بود. لطفاً دوباره تلاش کنید.',
  },
  // —— macOS 应用菜单（index.ts buildMacAppMenu；语言变化时重建） ——
  menuAbout: {
    'en-US': 'About FlowZ',
    ru: 'О программе FlowZ',
    fa: 'درباره FlowZ',
  },
  menuServices: {
    'en-US': 'Services',
    ru: 'Службы',
    fa: 'خدمات',
  },
  menuHide: {
    'en-US': 'Hide FlowZ',
    ru: 'Скрыть FlowZ',
    fa: 'پنهان کردن FlowZ',
  },
  menuHideOthers: {
    'en-US': 'Hide Others',
    ru: 'Скрыть остальные',
    fa: 'پنهان کردن بقیه',
  },
  menuUnhide: {
    'en-US': 'Show All',
    ru: 'Показать все',
    fa: 'نمایش همه',
  },
  menuQuit: {
    'en-US': 'Quit FlowZ',
    ru: 'Завершить FlowZ',
    fa: 'خروج از FlowZ',
  },
  menuEdit: {
    'en-US': 'Edit',
    ru: 'Правка',
    fa: 'ویرایش',
  },
  menuUndo: {
    'en-US': 'Undo',
    ru: 'Отменить',
    fa: 'واگرد',
  },
  menuRedo: {
    'en-US': 'Redo',
    ru: 'Повторить',
    fa: 'ازنو',
  },
  menuCut: {
    'en-US': 'Cut',
    ru: 'Вырезать',
    fa: 'برش',
  },
  menuCopy: {
    'en-US': 'Copy',
    ru: 'Скопировать',
    fa: 'کپی',
  },
  menuPaste: {
    'en-US': 'Paste',
    ru: 'Вставить',
    fa: 'چسباندن',
  },
  menuPasteMatchStyle: {
    'en-US': 'Paste and Match Style',
    ru: 'Вставить и сохранить стиль',
    fa: 'چسباندن و تطبیق سبک',
  },
  menuDelete: {
    'en-US': 'Delete',
    ru: 'Удалить',
    fa: 'حذف',
  },
  menuSelectAll: {
    'en-US': 'Select All',
    ru: 'Выбрать все',
    fa: 'انتخاب همه',
  },
  menuWindow: {
    'en-US': 'Window',
    ru: 'Окно',
    fa: 'پنجره',
  },
  menuMinimize: {
    'en-US': 'Minimize',
    ru: 'Свернуть',
    fa: 'کوچک کردن',
  },
  menuZoom: {
    'en-US': 'Zoom',
    ru: 'Изменить масштаб',
    fa: 'بزرگ‌نمایی',
  },
  menuFront: {
    'en-US': 'Bring All to Front',
    ru: 'Все окна — на передний план',
    fa: 'آوردن همه به جلو',
  },
} satisfies Record<string, Record<SupportedLanguage, string>>;

/** 主进程文案键（自 MESSAGES 自动派生，无需手维护 union）。 */
export type MainMessageKey = keyof typeof MESSAGES;

let currentLang: SupportedLanguage = DEFAULT_LANGUAGE;

/** 设主进程当前语言（据 config.language 单一真值源，启动 + config-change 由 index.ts 调用）。未知/auto/非法 → 回退默认。 */
export function setMainLanguage(lang: string | null | undefined): void {
  currentLang = resolveEffectiveLanguage(lang, null);
}

/** 取主进程当前语言（供测试/诊断）。 */
export function getMainLanguage(): SupportedLanguage {
  return currentLang;
}

/** 按当前语言取文案；缺键兜底回 DEFAULT_LANGUAGE，绝不返 undefined。 */
export function mt(key: MainMessageKey): string {
  const row = MESSAGES[key];
  return row[currentLang] ?? row[DEFAULT_LANGUAGE];
}

/** 全部文案键（供测试遍历校验）。 */
export const MAIN_MESSAGE_KEYS = Object.keys(MESSAGES) as MainMessageKey[];

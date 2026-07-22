import { BaseCustomModule } from "./sekant-intercept.browser.mjs";

export class BrowserExampleInterceptModule extends BaseCustomModule {
  constructor() {
    super("browser");
  }

  async initialize(data, metadata) {
    metadata = metadata ?? {};
    const { url, document } = metadata;
    const urlObj = URL.canParse(url) ? new URL(url) : {};

    const documentProperties = {};

    if (document && typeof document === "object") {
      documentProperties.title = document.title;
      documentProperties.has_referrer = document.referrer && document.referrer.length > 0 ? true : false;
      documentProperties.has_cookie = document.cookie ? true : false;
    }

    // Makes all webpage URL components and select document properties available as context
    const result = { ...urlObj, ...documentProperties };

    console.log("BrowserExampleInterceptModule initialized with metadata:", result);

    return result;
  }

  createModule(interimResults) {
    return {
      ...interimResults,
      title_has_word: (word) => typeof interimResults.title === 'string' && typeof word === 'string' && interimResults.title.toLowerCase().includes(word.toLowerCase()),
    };
  }
}

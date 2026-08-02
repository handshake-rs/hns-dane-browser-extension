const EVENT_NAMES = [
  "connect", "disconnect", "permissionsChanged", "modulesChanged",
  "accountsChanged", "balancesChanged", "transactionsChanged", "namesChanged",
  "nameMarketChanged", "priceRoundChanged", "marketIntentChanged",
  "swapSessionChanged", "walletLocked"
];
let provider = null;
const eventEntries = [];

window.addEventListener("hns:announceProvider", (event) => {
  if (provider || typeof event.detail?.provider?.request !== "function") return;
  provider = event.detail.provider;
  document.querySelector("#provider-state").textContent =
    `${event.detail.info?.name ?? "Handshake provider"} discovered`;
  enableActions(true);
  for (const name of EVENT_NAMES) provider.on(name, (payload) => logEvent(name, payload));
});
window.dispatchEvent(new Event("hns:requestProvider"));
setTimeout(() => {
  if (!provider) {
    document.querySelector("#provider-state").textContent =
      "No provider: this origin may be untrusted or wallet ABI v1 is unavailable";
  }
}, 1500);

on("#connect", async () => {
  await call("wallet_requestPermissions", {
    scopes: ["hns:accounts", "hns:read", "market:read", "swap:read"]
  });
  const accounts = await call("hns_requestAccounts");
  showOverview("HNS account", accounts);
});

on("#refresh-overview", async () => {
  const [hnsAccount, hnsBalance, btcAccount, btcBalance, ethAccount, ethBalance] =
    await Promise.all([
      call("hns_accounts"),
      call("hns_getBalance"),
      call("asset_getAccount", { module: "bitcoin" }),
      call("asset_getBalance", { module: "bitcoin" }),
      call("asset_getAccount", { module: "ethereum" }),
      call("asset_getBalance", { module: "ethereum" })
    ]);
  const overview = document.querySelector("#overview");
  overview.replaceChildren(
    card("HNS account", hnsAccount), card("HNS balance", hnsBalance),
    card("Bitcoin account", btcAccount), card("Bitcoin balance", btcBalance),
    card("Ethereum account", ethAccount), card("Ethereum balance", ethBalance)
  );
});

on("#refresh-names", async () => {
  output("#names-output", await call("hns_getNames"));
  output("#offers-output", await call("nameMarket_listOffers", {}));
});
on("#create-listing", async () => output(
  "#offers-output",
  await call("nameMarket_createFixedPriceOffer", {
    name: value("#listing-name"), priceBaseUnits: decimal("#listing-price")
  })
));
on("#accept-listing", async () => output(
  "#offers-output",
  await call("nameMarket_acceptOffer", { offerId: value("#offer-id") })
));

on("#refresh-intents", refreshIntents);
on("#publish-intent", async () => {
  const result = await call("swap_publishMarketIntent", {
    pair: value("#intent-pair"),
    hnsBaseUnits: decimal("#intent-base"),
    quoteBaseUnits: decimal("#intent-quote")
  });
  output("#swap-output", result);
  await refreshIntents();
});
on("#request-match", async () => output(
  "#swap-output",
  await call("swap_requestMatch", { marketIntentId: value("#intent-id") })
));
on("#accept-fill", async () => output(
  "#swap-output",
  await call("swap_acceptFill", { fillGrantId: value("#fill-id") })
));
on("#monitor-swap", async () => output(
  "#swap-output",
  await call("swap_getSession", { swapSessionId: value("#session-id") })
));
on("#refund-swap", async () => output(
  "#swap-output",
  await call("swap_refund", { swapSessionId: value("#session-id") })
));

async function refreshIntents() {
  const intents = await call("swap_listMarketIntents");
  const values = Array.isArray(intents) ? intents : intents?.intents ?? [];
  output("#btc-intents", values.filter((intent) => intent.pair === "HNS/BTC"));
  output("#eth-intents", values.filter((intent) => intent.pair === "HNS/ETH"));
}

async function call(method, params) {
  if (!provider) throw new Error("Handshake provider is unavailable");
  try {
    const result = await provider.request({ method, ...(params == null ? {} : { params }) });
    logEvent("response", { method, result });
    return result;
  } catch (error) {
    logEvent("error", { method, code: error.code, message: error.message });
    throw error;
  }
}

function logEvent(name, payload) {
  eventEntries.unshift({ at: new Date().toISOString(), name, payload });
  eventEntries.length = Math.min(eventEntries.length, 40);
  output("#event-log", eventEntries);
}

function showOverview(label, valueToShow) {
  const overview = document.querySelector("#overview");
  overview.replaceChildren(card(label, valueToShow));
}

function card(label, valueToShow) {
  const element = document.createElement("div");
  element.className = "card";
  const caption = document.createElement("span");
  caption.textContent = label;
  const content = document.createElement("strong");
  content.textContent = display(valueToShow);
  element.append(caption, content);
  return element;
}

function output(selector, valueToShow) {
  document.querySelector(selector).textContent = JSON.stringify(valueToShow, null, 2);
}

function display(valueToShow) {
  return typeof valueToShow === "string" ? valueToShow : JSON.stringify(valueToShow);
}

function on(selector, handler) {
  document.querySelector(selector).addEventListener("click", () => {
    void handler().catch((error) => output("#event-log", {
      code: error.code ?? "error", message: error.message
    }));
  });
}

function value(selector) {
  const result = document.querySelector(selector).value.trim();
  if (!result) throw new Error("Complete the required field");
  return result;
}

function decimal(selector) {
  const result = value(selector);
  if (!/^(0|[1-9][0-9]*)$/.test(result)) throw new Error("Use integer base units");
  return result;
}

function enableActions(enabled) {
  for (const button of document.querySelectorAll("button")) button.disabled = !enabled;
}

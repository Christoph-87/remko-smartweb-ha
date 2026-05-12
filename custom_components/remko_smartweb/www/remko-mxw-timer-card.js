class RemkoMxwTimerCard extends HTMLElement {
  setConfig(config) {
    if (!config.entity) {
      throw new Error("entity is required");
    }
    this.config = {
      title: "REMKO MXW timer",
      device_name: "",
      ...config,
    };
  }

  set hass(hass) {
    this._hass = hass;
    this.render();
  }

  getCardSize() {
    return 4;
  }

  render() {
    if (!this.config || !this._hass) return;
    const state = this._hass.states[this.config.entity];
    const slots = this.readSlots(state);
    this.innerHTML = `
      <ha-card>
        <div class="remko-card">
          <div class="remko-header">
            <div>
              <div class="remko-title">${this.escape(this.config.title)}</div>
            <div class="remko-subtitle">${slots.filter((slot) => slot.active).length} active programs</div>
            </div>
            <mwc-button dense id="save">Save</mwc-button>
          </div>
          <div class="remko-grid">
            ${slots.map((slot, index) => this.slotRow(slot, index)).join("")}
          </div>
        </div>
        <style>
          .remko-card { padding: 16px; }
          .remko-header {
            align-items: center;
            display: flex;
            justify-content: space-between;
            gap: 12px;
            margin-bottom: 12px;
          }
          .remko-title { font-size: 18px; font-weight: 500; }
          .remko-subtitle { color: var(--secondary-text-color); font-size: 13px; margin-top: 2px; }
          .remko-grid { display: grid; gap: 8px; }
          .remko-row {
            align-items: center;
            display: grid;
            grid-template-columns: 34px minmax(70px, 1fr) 92px 96px 52px;
            gap: 8px;
            min-height: 40px;
          }
          .remko-slot { color: var(--secondary-text-color); font-size: 12px; text-align: right; }
          select, input {
            background: var(--card-background-color);
            border: 1px solid var(--divider-color);
            border-radius: 6px;
            color: var(--primary-text-color);
            min-height: 34px;
            padding: 0 8px;
          }
          input[type="time"] { font: inherit; }
          ha-switch { justify-self: center; }
          @media (max-width: 480px) {
            .remko-row { grid-template-columns: 30px 1fr 80px 48px; }
            .remko-action { grid-column: 2 / 5; }
          }
        </style>
      </ha-card>
    `;
    this.querySelector("#save").addEventListener("click", () => this.save());
  }

  readSlots(state) {
    const incoming = state?.attributes?.slots || [];
    const ids = ["1195", "1196", "1197", "1198", "1210", "1211"];
    return ids.map((id, index) => ({
      id,
      active: false,
      start_day: 1,
      end_day: 5,
      time: "07:00",
      mode: index % 2 === 0 ? "on" : "off",
      mode_value: index % 2 === 0 ? 1 : 2,
      ...(incoming.find((slot) => String(slot.id) === id) || {}),
    }));
  }

  slotRow(slot, index) {
    return `
      <div class="remko-row" data-index="${index}" data-id="${this.escape(slot.id)}">
        <div class="remko-slot">${index + 1}</div>
        <select class="days">
          ${this.dayOptions(slot.start_day, slot.end_day)}
        </select>
        <input class="time" type="time" step="900" value="${this.escape(slot.time)}">
        <select class="remko-action action">
          ${this.modeOptions(slot)}
        </select>
        <ha-switch class="active" ${slot.active ? "checked" : ""}></ha-switch>
      </div>
    `;
  }

  modeOptions(slot) {
    const value = Number(slot.mode_value ?? (slot.mode === "off" ? 2 : 1));
    const options = [
      [1, "On"],
      [2, "Off"],
    ];
    if (!options.some(([optionValue]) => optionValue === value)) {
      options.push([value, `Value ${value}`]);
    }
    return options
      .map(([optionValue, label]) => {
        const selected = optionValue === value ? "selected" : "";
        return `<option value="${optionValue}" ${selected}>${this.escape(label)}</option>`;
      })
      .join("");
  }

  dayOptions(start, end) {
    const ranges = [
      [1, 5, "Mon-Fri"],
      [6, 7, "Sat-Sun"],
      [1, 7, "Every day"],
      [1, 1, "Mon"],
      [2, 2, "Tue"],
      [3, 3, "Wed"],
      [4, 4, "Thu"],
      [5, 5, "Fri"],
      [6, 6, "Sat"],
      [7, 7, "Sun"],
    ];
    return ranges
      .map(([rangeStart, rangeEnd, label]) => {
        const selected = rangeStart === Number(start) && rangeEnd === Number(end) ? "selected" : "";
        return `<option value="${rangeStart}-${rangeEnd}" ${selected}>${label}</option>`;
      })
      .join("");
  }

  save() {
    const rows = [...this.querySelectorAll(".remko-row")];
    const slots = rows.map((row) => {
      const [startDay, endDay] = row.querySelector(".days").value.split("-").map(Number);
      return {
        id: row.dataset.id,
        active: row.querySelector(".active").checked,
        start_day: startDay,
        end_day: endDay,
        time: row.querySelector(".time").value,
        mode_value: Number(row.querySelector(".action").value),
      };
    });
    this._hass.callService("remko_smartweb", "set_mxw_timer_slots", {
      device_name: this.config.device_name || undefined,
      slots,
    });
  }

  escape(value) {
    return String(value ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }
}

customElements.define("remko-mxw-timer-card", RemkoMxwTimerCard);

window.customCards = window.customCards || [];
window.customCards.push({
  type: "remko-mxw-timer-card",
  name: "REMKO MXW timer card",
  description: "Compact editor for REMKO SmartWeb MXW timer slots.",
});

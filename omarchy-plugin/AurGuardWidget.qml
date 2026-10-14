import QtQuick
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Ui

// AUR Guard: shield in the bar, red with a count when an installed AUR package
// is flagged. Popup shows DB/scan status, findings, and scan/update actions.
Panel {
  id: root
  moduleName: "io.github.ahmadrun.aurguard"
  ipcTarget: "io.github.ahmadrun.aurguard"

  readonly property string shieldGlyph: "\uf132"   // nf-fa-shield
  readonly property string cmd: String(setting("aurguardPath", "aurguard"))
  readonly property int refreshMinutes: Math.max(1, Number(setting("refreshMinutes", 10)) || 10)

  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

  property var status: null
  property string busy: ""          // "", "scan", "update"
  property string lastError: ""

  readonly property var findings: status && status.last_scan ? status.last_scan.findings : []
  readonly property var serious: findings.filter(function(f) { return f.severity === "critical" || f.severity === "high" })
  readonly property bool danger: serious.length > 0
  readonly property bool protectedOn: status && status.timers && status.timers.scan === "active"

  readonly property string barText: {
    if (busy !== "") return shieldGlyph + (bar && bar.vertical ? "" : "  …")
    if (danger && !(bar && bar.vertical)) return shieldGlyph + "  " + serious.length
    return shieldGlyph
  }

  function sevColor(sev, fg) {
    if (sev === "critical" || sev === "high") return Color.urgent
    if (sev === "medium") return Color.accent
    return Color.muted
  }

  function ago(ts) {
    if (!ts) return "never"
    var s = Math.max(0, Date.now() / 1000 - ts)
    if (s < 90) return "just now"
    if (s < 5400) return Math.round(s / 60) + " min ago"
    if (s < 129600) return Math.round(s / 3600) + " h ago"
    return Math.round(s / 86400) + " days ago"
  }

  // Run aurguard with ~/.local/bin on PATH (the shell's environment may not have it).
  function aurguard(args) {
    return ["sh", "-c", "PATH=\"$HOME/.local/bin:$PATH\"; exec \"$0\" \"$@\"", cmd].concat(args)
  }

  function refresh() {
    if (!statusProc.running) statusProc.running = true
  }

  function run(kind) {
    if (busy !== "") return
    busy = kind
    lastError = ""
    actionProc.command = kind === "scan"
      ? ["sh", "-c", "PATH=\"$HOME/.local/bin:$PATH\"; \"$0\" scan --update --notify --json -q >/dev/null; s=$?; [ $s -le 3 ] || exit $s", cmd]
      : aurguard([kind])   // update / enable / disable
    actionProc.running = true
  }

  function openTerminalScan() {
    Quickshell.execDetached(["omarchy-launch-floating-terminal-with-presentation", cmd + " scan"])
  }

  Process {
    id: statusProc
    command: root.aurguard(["status", "--json"])
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        try { root.status = JSON.parse(String(text || "")) }
        catch (e) { root.lastError = "aurguard not found: set its path in plugin settings" }
      }
    }
  }

  Process {
    id: actionProc
    stderr: StdioCollector { waitForEnd: true; id: actionErr }
    onExited: function(code) {
      if (code !== 0 && root.busy !== "scan") root.lastError = String(actionErr.text || "").trim().split("\n").pop()
      root.busy = ""
      root.refresh()
    }
  }

  //   qs ipc -p /usr/share/omarchy/shell call io.github.ahmadrun.aurguard.actions scan
  IpcHandler {
    target: "io.github.ahmadrun.aurguard.actions"
    function scan(): void { root.run("scan") }
    function update(): void { root.run("update") }
    function refresh(): void { root.refresh() }
  }

  Timer {
    interval: root.refreshMinutes * 60000
    running: true
    repeat: true
    triggeredOnStart: true
    onTriggered: root.refresh()
  }

  // ---- Bar pill

  WidgetButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    text: root.barText
    active: root.danger
    horizontalMargin: 8.75
    fixedWidth: root.bar && root.bar.vertical ? Style.bar.statusSlot : -1
    tooltipText: {
      if (root.lastError) return "AUR Guard: " + root.lastError
      if (root.busy === "scan") return "AUR Guard: scanning…"
      if (root.danger) return "AUR Guard: " + root.serious.length + " dangerous package" + (root.serious.length > 1 ? "s" : "")
      return "AUR Guard: protected · last scan " + root.ago(root.status && root.status.last_scan ? root.status.last_scan.time : 0)
    }
    onPressed: function(b) {
      if (b === Qt.MiddleButton) root.run("scan")
      else { root.refresh(); root.toggle() }
    }
  }

  // ---- Popup

  KeyboardPanel {
    id: panel
    anchorItem: button
    owner: root
    bar: root.bar
    open: root.opened
    focusTarget: keyCatcher
    contentWidth: panel.fittedContentWidth(Style.space(380))
    contentHeight: panel.fittedContentHeight(column.implicitHeight)

    readonly property color fg: root.bar ? root.bar.foreground : Color.foreground
    readonly property string fontName: root.bar ? root.bar.fontFamily : Style.font.family

    PanelKeyCatcher {
      id: keyCatcher
      anchors.fill: parent
      onCloseRequested: root.close()
      onTabRequested: function(direction) { root.switchPanel(direction) }

      Column {
        id: column
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.top: parent.top
        spacing: Style.space(14)

        PanelHero {
          foreground: panel.fg
          fontFamily: panel.fontName
          iconComponent: Component {
            Text {
              textFormat: Text.PlainText
              text: root.shieldGlyph
              color: root.danger ? Color.urgent : Color.accent
              font.family: panel.fontName
              font.pixelSize: Style.font.display
            }
          }
          title: root.busy === "scan" ? "Scanning AUR packages…"
            : root.danger ? root.serious.length + " dangerous package" + (root.serious.length > 1 ? "s" : "")
            : "Your system is protected"
          meta: root.status && root.status.last_scan
            ? root.status.last_scan.scanned + " AUR pkgs · scanned " + root.ago(root.status.last_scan.time)
            : "Not scanned yet"
          detail: root.status
            ? "DB v" + root.status.db_version
            : ""
        }

        Text {
          visible: root.lastError !== ""
          width: parent.width
          wrapMode: Text.Wrap
          text: root.lastError
          color: Color.urgent
          font.family: panel.fontName
          font.pixelSize: Style.font.bodySmall
        }

        // ---- Findings
        Column {
          width: parent.width
          spacing: Style.space(6)
          visible: root.findings.length > 0

          PanelSectionHeader {
            text: "FINDINGS"
            foreground: panel.fg
            fontFamily: panel.fontName
          }

          Repeater {
            model: root.findings
            delegate: Column {
              required property var modelData
              width: parent.width
              spacing: Style.space(1)

              Row {
                spacing: Style.space(8)
                Text {
                  text: modelData.severity.toUpperCase()
                  color: root.sevColor(modelData.severity, panel.fg)
                  font.family: panel.fontName
                  font.pixelSize: Style.font.bodySmall
                  font.bold: true
                }
                Text {
                  text: modelData.package
                  color: panel.fg
                  font.family: panel.fontName
                  font.pixelSize: Style.font.body
                  font.bold: true
                }
              }
              Text {
                width: parent.width
                text: modelData.reason
                wrapMode: Text.Wrap
                color: panel.fg
                opacity: 0.65
                font.family: panel.fontName
                font.pixelSize: Style.font.bodySmall
              }
            }
          }

          Button {
            visible: root.danger
            text: "Show details & fix"
            iconText: "\uf0ad"
            foreground: panel.fg
            fontFamily: panel.fontName
            bordered: true
            onClicked: { root.close(); root.openTerminalScan() }
          }
        }

        PanelSeparator { foreground: panel.fg }

        // ---- Protection
        Column {
          width: parent.width
          spacing: Style.space(8)

          PanelSectionHeader {
            text: "PROTECTION"
            foreground: panel.fg
            fontFamily: panel.fontName
          }

          Toggle {
            width: parent.width
            label: "Automatic protection"
            description: "Update threat DB every 6 h, scan daily, notify on danger"
            checked: root.protectedOn
            foreground: panel.fg
            fontFamily: panel.fontName
            onClicked: root.run(root.protectedOn ? "disable" : "enable")
          }

          Row {
            spacing: Style.spacing.md

            Button {
              text: root.busy === "scan" ? "Scanning…" : "Scan now"
              iconText: String.fromCodePoint(0xF0349)
              iconSpinning: root.busy === "scan"
              foreground: panel.fg
              fontFamily: panel.fontName
              bordered: true
              onClicked: root.run("scan")
            }

            Button {
              text: root.busy === "update" ? "Updating…" : "Update DB"
              iconText: String.fromCodePoint(0xF06B0)
              iconSpinning: root.busy === "update"
              foreground: panel.fg
              fontFamily: panel.fontName
              bordered: true
              onClicked: root.run("update")
            }
          }
        }
      }
    }
  }
}

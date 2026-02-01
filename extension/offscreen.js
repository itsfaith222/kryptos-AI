/**
 * Offscreen document for playing voice alerts when background detects high risk.
 * Service workers cannot play audio; this page receives playVoice messages and plays the MP3.
 */
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg.action !== 'playVoice' || !msg.audioSrc) {
    return
  }
  try {
    const audio = new Audio(msg.audioSrc)
    audio.volume = 1
    audio.play()
    audio.onended = () => sendResponse({ ok: true })
    audio.onerror = () => sendResponse({ ok: false })
  } catch (e) {
    sendResponse({ ok: false })
  }
  return true
})

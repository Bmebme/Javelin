import { spawn } from 'node:child_process';
import { createServer as createNetServer } from 'node:net';
import { randomBytes, randomUUID } from 'node:crypto';
import { writeFile, rename, rm } from 'node:fs/promises';
import { join } from 'node:path';

export const SHARED_CONNECTION_FILE = 'opencode-server.json';
// Match non-interactive `opencode run` session creation: attaching a TUI must
// not introduce questions or plan-mode gates into the existing audit workflow.
export const RUN_PERMISSIONS = ['question', 'plan_enter', 'plan_exit'].map(permission => ({ permission, action: 'deny', pattern: '*' }));

// Both children belong to the launcher's owned tree. The monitor controls this
// tree, including the server that actually executes the audit.
export async function startSharedRun(spec, { environment, output, spawnProcess = spawn }) {
  const connectionPath = join(spec.state_directory, SHARED_CONNECTION_FILE);
  const generation = randomUUID();
  const password = randomBytes(32).toString('hex');
  const env = { ...environment, OPENCODE_SERVER_USERNAME: 'opencode', OPENCODE_SERVER_PASSWORD: password };
  let server, runner, stopping, readyTimer, request, sessionId, runFinished, wake;
  let paused = false, serverFailed = false, controls = Promise.resolve();
  const notify = message => { if (spec.controllable && process.connected) process.send(message, () => {}); };
  const waitUntilResumed = async () => { while (paused && !stopping) await new Promise(resolve => { wake = resolve; }); };
  const children = new Set();
  async function stop() {
    if (stopping) return stopping;
    stopping = (async () => {
      clearTimeout(readyTimer);
      paused = false; wake?.();
      await rm(connectionPath, { force: true });
      await Promise.all([...children].map(child => new Promise(resolve => {
        if (child.exitCode !== null || child.signalCode !== null) return resolve();
        const timer = setTimeout(() => child.kill('SIGKILL'), 2500);
        child.once('close', () => { clearTimeout(timer); resolve(); });
        child.kill('SIGTERM');
      })));
    })();
    return stopping;
  }
  const onSignal = () => { void stop(); };
  const onDisconnect = () => { void stop(); };
  const onControl = message => {
    if (!spec.controllable || message?.type !== 'audit-control' || !['pause', 'resume', 'stop'].includes(message.action)) return;
    controls = controls.then(async () => {
      if (message.action === 'stop') await stop();
      else if (stopping) throw new Error('任务正在结束。');
      else if (message.action === 'pause') {
        paused = true;
        try {
          if (request && sessionId && runner && runner.exitCode === null && runner.signalCode === null) {
            // Stop the submitting client first: an early pause must not race a
            // client that has not sent its initial prompt yet.
            runner.kill('SIGTERM');
            let timer;
            try { await Promise.race([runFinished, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('OpenCode 会话未确认暂停。')), 7000); })]); }
            finally { clearTimeout(timer); }
            await request(`/session/${encodeURIComponent(sessionId)}/abort`, { method: 'POST' });
          }
        } catch (error) { await stop(); throw error; }
      } else { paused = false; wake?.(); }
      notify({ type: 'audit-control-result', id: message.id });
    }).catch(error => { notify({ type: 'audit-control-result', id: message.id, error: error.message }); });
  };
  for (const signal of ['SIGINT', 'SIGTERM', 'SIGHUP']) process.on(signal, onSignal);
  if (spec.controllable) { process.on('message', onControl); process.on('disconnect', onDisconnect); }
  const start = args => {
    if (stopping) throw new Error('任务启动已取消。');
    const child = spawnProcess(spec.command, args, { cwd: spec.cwd, env, stdio: ['ignore', 'pipe', 'pipe'], shell: false, windowsHide: true });
    children.add(child);
    if (Number.isSafeInteger(child.pid)) {
      notify({ type: 'audit-child', pid: child.pid, active: true });
      child.once('close', () => notify({ type: 'audit-child', pid: child.pid, active: false }));
    }
    return child;
  };
  try {
    await rm(connectionPath, { force: true });
    const allocatePort = () => new Promise(resolve => {
      const probe = createNetServer();
      probe.unref();
      probe.once('error', () => resolve(0));
      probe.listen(0, '127.0.0.1', () => {
        const addr = probe.address();
        const port = typeof addr === 'object' && addr && addr.port > 0 ? addr.port : 0;
        probe.close(() => resolve(port));
      });
    });
    const scrubDetail = value => {
      let text = String(value ?? '').replace(/\s+/g, ' ').trim();
      if (password) text = text.replaceAll(password, '[REDACTED]');
      return text
        .replace(/\bBearer\s+[A-Za-z0-9._~+\/-]+=*/gi, 'Bearer [REDACTED]')
        .replace(/(["']?(?:api[_-]?key|apikey|token|secret|password|authorization|cookie)["']?\s*[:=]\s*["']?)[^\s,"']+/gi, '$1[REDACTED]')
        .slice(0, 320);
    };
    const args = [...spec.args];
    const sessionIndex = args.indexOf('--session');
    const requestedId = sessionIndex >= 0 ? args[sessionIndex + 1] : null;
    const titleIndex = args.indexOf('--title');
    let url = '';
    let session = null;
    for (let attempt = 0; attempt < 2; attempt += 1) {
      let serverStderr = '';
      const bindPort = await allocatePort();
      server = start(['serve', '--hostname', '127.0.0.1', '--port', String(bindPort)]);
      url = await new Promise((resolve, reject) => {
        let buffer = '';
        readyTimer = setTimeout(() => reject(new Error(`OpenCode 服务启动超时。${serverStderr ? ' stderr: ' + scrubDetail(serverStderr) : ''}`)), 30_000);
        const failed = () => reject(new Error(`OpenCode 服务在就绪前退出。${serverStderr ? ' stderr: ' + scrubDetail(serverStderr) : ''}`));
        server.once('error', failed); server.once('close', failed);
        server.stderr.on('data', chunk => { serverStderr = (serverStderr + String(chunk)).slice(-2048); });
        server.stdout.on('data', chunk => {
          buffer = (buffer + chunk).slice(-8192);
          const match = buffer.match(/opencode server listening on (http:\/\/127\.0\.0\.1:(\d+))/);
          if (match && Number(match[2]) > 0 && Number(match[2]) <= 65535) { clearTimeout(readyTimer); resolve(match[1]); }
        });
      });
      request = async (path, options = {}) => {
        let response;
        try {
          response = await fetch(`${url}${path}${path.includes('?') ? '&' : '?'}directory=${encodeURIComponent(spec.cwd)}`, {
            ...options, headers: { Authorization: `Basic ${Buffer.from(`opencode:${password}`).toString('base64')}`, 'Content-Type': 'application/json' },
            signal: AbortSignal.timeout(30_000), redirect: 'error',
          });
        } catch (fetchErr) {
          const tail = scrubDetail(serverStderr);
          throw new Error(`${fetchErr.message}${tail ? ` (stderr: ${tail})` : ''}`);
        }
        if (!response.ok) {
          const bodyText = scrubDetail(await response.text().catch(() => ''));
          const stderrText = scrubDetail(serverStderr);
          const detail = bodyText || stderrText;
          const err = new Error(`OpenCode 会话连接失败（HTTP ${response.status}）${detail ? `：${detail}` : '。'}`);
          err.statusCode = response.status;
          err.detail = `${bodyText} ${stderrText}`.trim();
          throw err;
        }
        return response.json();
      };
      try {
        session = requestedId
          ? await request(`/session/${encodeURIComponent(requestedId)}`)
          : await request('/session', { method: 'POST', body: JSON.stringify({ title: titleIndex >= 0 ? args[titleIndex + 1] : spec.audit_id, permission: RUN_PERMISSIONS }) });
        break;
      } catch (err) {
        const canStripSubagentDepth = attempt === 0 && !requestedId && err?.statusCode === 500
          && /subagent_depth/i.test(String(err?.detail || err?.message || ''))
          && typeof env.OPENCODE_CONFIG_CONTENT === 'string' && env.OPENCODE_CONFIG_CONTENT.includes('subagent_depth');
        if (!canStripSubagentDepth) throw err;
        try {
          const parsed = JSON.parse(env.OPENCODE_CONFIG_CONTENT);
          delete parsed.subagent_depth;
          env.OPENCODE_CONFIG_CONTENT = JSON.stringify(parsed);
        } catch {
          throw err;
        }
        const deadServer = server;
        children.delete(deadServer);
        await new Promise(resolve => {
          if (deadServer.exitCode !== null || deadServer.signalCode !== null) return resolve();
          const t = setTimeout(() => { try { deadServer.kill('SIGKILL'); } catch {} resolve(); }, 1500);
          deadServer.once('close', () => { clearTimeout(t); resolve(); });
          try { deadServer.kill('SIGTERM'); } catch { clearTimeout(t); resolve(); }
        });
      }
    }
    if (!/^ses_[A-Za-z0-9_-]+$/.test(session?.id ?? '') || requestedId && session.id !== requestedId) throw new Error('OpenCode 返回了不匹配的会话。');
    sessionId = session.id;
    if (stopping || server.exitCode !== null || server.signalCode !== null) throw new Error('OpenCode 服务已退出。');
    if (!requestedId) args.splice(1, 0, '--session', session.id);
    args.splice(1, 0, '--attach', url);
    const binding = { schema_version: 'opencode-shared-run.v1', audit_id: spec.audit_id, generation,
      session_id: session.id, url, username: 'opencode', password, command: spec.command,
      directory: spec.cwd, server_pid: server.pid, launcher_pid: process.pid, created_at: new Date().toISOString() };
    const temporaryPath = `${connectionPath}.${generation}.tmp`;
    await writeFile(temporaryPath, `${JSON.stringify(binding)}\n`, { mode: 0o600 });
    await rename(temporaryPath, connectionPath);
    output(`${JSON.stringify({ type: 'session_bound', sessionID: session.id, shared_server: true, generation })}\n`);
    server.once('close', () => {
      if (!stopping) {
        serverFailed = true;
        output(`${JSON.stringify({ type: 'error', sessionID: session.id, error: { message: 'OpenCode 服务异常退出。' } })}\n`);
        void stop();
      }
    });
    while (!stopping) {
      await waitUntilResumed();
      if (stopping) break;
      runner = start(args);
      for (const stream of [runner.stdout, runner.stderr]) stream.on('data', output);
      runFinished = new Promise((resolve, reject) => {
        runner.once('error', () => reject(new Error('OpenCode JSON 客户端启动失败。')));
        runner.once('close', (code, signal) => resolve({ code, signal }));
      });
      const result = await runFinished;
      if (serverFailed) return { code: 1, signal: null };
      if (!paused || stopping) return result;
      // Resume the same session, retaining its context and the task board state.
      args[args.length - 1] = '继续当前审计会话。先读取当前任务面板与既有制品，从尚未完成的步骤继续，保持原冻结范围与授权限制。';
    }
    return { code: serverFailed ? 1 : 0, signal: 'SIGTERM' };
  } finally {
    await stop();
    await rm(connectionPath, { force: true });
    for (const signal of ['SIGINT', 'SIGTERM', 'SIGHUP']) process.off(signal, onSignal);
    process.off('message', onControl); process.off('disconnect', onDisconnect);
  }
}

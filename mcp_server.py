#!/usr/bin/env python3
"""
Enhanced Kali Linux API Server with Advanced Capabilities
- Parallel command execution
- Session management for persistent shells
- Job queue system
- Advanced timeout handling
- Extended tool support
"""

import argparse
import json
import logging
import os
import queue
import signal
import subprocess
import sys
import threading
import time
import traceback
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from flask import Flask, jsonify, request

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)

# Configuration
API_PORT = int(os.environ.get("API_PORT", 5000))
DEBUG_MODE = os.environ.get("DEBUG_MODE", "0").lower() in ("1", "true", "yes", "y")
DEFAULT_TIMEOUT = 3600  # 1 hour default timeout for complex tasks
MAX_WORKERS = 10  # Maximum parallel jobs

app = Flask(__name__)


class JobStatus(Enum):
    """Job status enumeration"""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"


@dataclass
class Job:
    """Job data structure"""

    job_id: str
    command: str
    status: JobStatus
    created_at: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    stdout: str = ""
    stderr: str = ""
    return_code: Optional[int] = None
    timeout: int = DEFAULT_TIMEOUT
    background: bool = False

    def to_dict(self):
        result = asdict(self)
        result["status"] = self.status.value
        return result


class SessionManager:
    """Manages persistent shell sessions"""

    def __init__(self):
        self.sessions = {}
        self.lock = threading.Lock()
        logger.info("SessionManager initialized")

    def create_session(
        self, session_id: Optional[str] = None, shell: str = "/bin/bash"
    ) -> str:
        """Create a new persistent shell session"""
        if session_id is None:
            session_id = str(uuid.uuid4())

        with self.lock:
            if session_id in self.sessions:
                logger.warning(f"Session {session_id} already exists")
                return session_id

            try:
                process = subprocess.Popen(
                    [shell],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=0,
                    preexec_fn=os.setsid if os.name != "nt" else None,
                )

                self.sessions[session_id] = {
                    "process": process,
                    "shell": shell,
                    "created_at": datetime.now().isoformat(),
                    "last_used": datetime.now().isoformat(),
                    "output_buffer": [],
                    "lock": threading.Lock(),
                }

                logger.info(f"Created session {session_id} with shell {shell}")
                return session_id

            except Exception as e:
                logger.error(f"Failed to create session: {str(e)}")
                raise

    def execute_in_session(
        self, session_id: str, command: str, timeout: int = 30
    ) -> Dict[str, Any]:
        """Execute a command in an existing session"""
        with self.lock:
            if session_id not in self.sessions:
                return {"error": f"Session {session_id} not found", "success": False}

            session = self.sessions[session_id]

        with session["lock"]:
            try:
                process = session["process"]

                # Check if process is still alive
                if process.poll() is not None:
                    return {"error": "Session terminated", "success": False}

                # Send command
                process.stdin.write(command + "\n")
                process.stdin.flush()

                # Add marker to detect end of output
                marker = f"__END_MARKER_{uuid.uuid4().hex}__"
                process.stdin.write(f'echo "{marker}"\n')
                process.stdin.flush()

                # Read output until marker
                output = []
                start_time = time.time()

                while time.time() - start_time < timeout:
                    try:
                        line = process.stdout.readline()
                        if marker in line:
                            break
                        output.append(line)
                    except Exception as e:
                        logger.error(f"Error reading output: {str(e)}")
                        break

                session["last_used"] = datetime.now().isoformat()

                return {
                    "stdout": "".join(output),
                    "success": True,
                    "session_id": session_id,
                }

            except Exception as e:
                logger.error(f"Error executing in session: {str(e)}")
                return {"error": str(e), "success": False}

    def close_session(self, session_id: str) -> bool:
        """Close a session"""
        with self.lock:
            if session_id not in self.sessions:
                return False

            session = self.sessions[session_id]
            try:
                session["process"].terminate()
                session["process"].wait(timeout=5)
            except:
                try:
                    session["process"].kill()
                except:
                    pass

            del self.sessions[session_id]
            logger.info(f"Closed session {session_id}")
            return True

    def list_sessions(self) -> List[Dict[str, Any]]:
        """List all active sessions"""
        with self.lock:
            return [
                {
                    "session_id": sid,
                    "shell": sess["shell"],
                    "created_at": sess["created_at"],
                    "last_used": sess["last_used"],
                    "alive": sess["process"].poll() is None,
                }
                for sid, sess in self.sessions.items()
            ]

    def cleanup_dead_sessions(self):
        """Remove dead sessions"""
        with self.lock:
            dead_sessions = [
                sid
                for sid, sess in self.sessions.items()
                if sess["process"].poll() is not None
            ]
            for sid in dead_sessions:
                del self.sessions[sid]
                logger.info(f"Cleaned up dead session {sid}")


class JobManager:
    """Manages job queue and execution"""

    def __init__(self, max_workers: int = MAX_WORKERS):
        self.jobs = {}
        self.job_queue = queue.Queue()
        self.workers = []
        self.max_workers = max_workers
        self.lock = threading.Lock()
        self.running = True

        # Start worker threads
        for i in range(max_workers):
            worker = threading.Thread(target=self._worker, daemon=True)
            worker.start()
            self.workers.append(worker)

        logger.info(f"JobManager initialized with {max_workers} workers")

    def _worker(self):
        """Worker thread that processes jobs from queue"""
        while self.running:
            try:
                job_id = self.job_queue.get(timeout=1)
                self._execute_job(job_id)
                self.job_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Worker error: {str(e)}")

    def _execute_job(self, job_id: str):
        """Execute a job"""
        with self.lock:
            if job_id not in self.jobs:
                return
            job = self.jobs[job_id]

        job.status = JobStatus.RUNNING
        job.started_at = datetime.now().isoformat()

        logger.info(f"Executing job {job_id}: {job.command}")

        try:
            process = subprocess.Popen(
                job.command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                preexec_fn=os.setsid if os.name != "nt" else None,
            )

            # Read output with timeout
            try:
                stdout, stderr = process.communicate(timeout=job.timeout)
                job.stdout = stdout
                job.stderr = stderr
                job.return_code = process.returncode
                job.status = (
                    JobStatus.COMPLETED if process.returncode == 0 else JobStatus.FAILED
                )

            except subprocess.TimeoutExpired:
                # Kill process group
                try:
                    if os.name != "nt":
                        os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                    else:
                        process.kill()
                except:
                    pass

                stdout, stderr = process.communicate()
                job.stdout = stdout or ""
                job.stderr = (stderr or "") + f"\n[TIMEOUT after {job.timeout}s]"
                job.return_code = -1
                job.status = JobStatus.TIMEOUT

        except Exception as e:
            job.stderr = f"Execution error: {str(e)}\n{traceback.format_exc()}"
            job.return_code = -1
            job.status = JobStatus.FAILED

        job.completed_at = datetime.now().isoformat()
        logger.info(f"Job {job_id} completed with status {job.status.value}")

    def submit_job(
        self, command: str, timeout: int = DEFAULT_TIMEOUT, background: bool = False
    ) -> str:
        """Submit a new job"""
        job_id = str(uuid.uuid4())

        job = Job(
            job_id=job_id,
            command=command,
            status=JobStatus.PENDING,
            created_at=datetime.now().isoformat(),
            timeout=timeout,
            background=background,
        )

        with self.lock:
            self.jobs[job_id] = job

        self.job_queue.put(job_id)
        logger.info(f"Submitted job {job_id}")

        return job_id

    def get_job(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Get job status and results"""
        with self.lock:
            if job_id not in self.jobs:
                return None
            return self.jobs[job_id].to_dict()

    def list_jobs(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        """List all jobs, optionally filtered by status"""
        with self.lock:
            jobs = list(self.jobs.values())

        if status:
            try:
                status_enum = JobStatus(status)
                jobs = [j for j in jobs if j.status == status_enum]
            except ValueError:
                pass

        return [j.to_dict() for j in jobs]

    def cancel_job(self, job_id: str) -> bool:
        """Cancel a pending or running job"""
        with self.lock:
            if job_id not in self.jobs:
                return False

            job = self.jobs[job_id]

            if job.status == JobStatus.PENDING:
                job.status = JobStatus.CANCELLED
                return True

            # For running jobs, we can't easily cancel them
            # Would need to track process objects
            return False

    def cleanup_old_jobs(self, max_age_hours: int = 24):
        """Remove old completed jobs"""
        cutoff = datetime.now().timestamp() - (max_age_hours * 3600)

        with self.lock:
            old_jobs = [
                jid
                for jid, job in self.jobs.items()
                if job.status
                in [JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELLED]
                and datetime.fromisoformat(job.created_at).timestamp() < cutoff
            ]

            for jid in old_jobs:
                del self.jobs[jid]

            if old_jobs:
                logger.info(f"Cleaned up {len(old_jobs)} old jobs")


# Global managers
session_manager = SessionManager()
job_manager = JobManager()


def execute_command_sync(
    command: str, timeout: int = DEFAULT_TIMEOUT
) -> Dict[str, Any]:
    """Execute a command synchronously"""
    logger.info(f"Executing command: {command}")

    try:
        process = subprocess.Popen(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            preexec_fn=os.setsid if os.name != "nt" else None,
        )

        try:
            stdout, stderr = process.communicate(timeout=timeout)

            return {
                "stdout": stdout,
                "stderr": stderr,
                "return_code": process.returncode,
                "success": process.returncode == 0,
                "timed_out": False,
            }

        except subprocess.TimeoutExpired:
            try:
                if os.name != "nt":
                    os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                else:
                    process.kill()
            except:
                pass

            stdout, stderr = process.communicate()

            return {
                "stdout": stdout or "",
                "stderr": (stderr or "") + f"\n[TIMEOUT after {timeout}s]",
                "return_code": -1,
                "success": False,
                "timed_out": True,
            }

    except Exception as e:
        logger.error(f"Error executing command: {str(e)}")
        return {
            "stdout": "",
            "stderr": f"Error: {str(e)}\n{traceback.format_exc()}",
            "return_code": -1,
            "success": False,
            "timed_out": False,
        }


# ====================== API ENDPOINTS ======================


@app.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint"""
    tools = {
        "nmap": os.system("which nmap > /dev/null 2>&1") == 0,
        "gobuster": os.system("which gobuster > /dev/null 2>&1") == 0,
        "ffuf": os.system("which ffuf > /dev/null 2>&1") == 0,
        "nikto": os.system("which nikto > /dev/null 2>&1") == 0,
        "sqlmap": os.system("which sqlmap > /dev/null 2>&1") == 0,
        "hydra": os.system("which hydra > /dev/null 2>&1") == 0,
        "john": os.system("which john > /dev/null 2>&1") == 0,
        "metasploit": os.system("which msfconsole > /dev/null 2>&1") == 0,
        "burpsuite": os.system("which burpsuite > /dev/null 2>&1") == 0,
        "nuclei": os.system("which nuclei > /dev/null 2>&1") == 0,
        "feroxbuster": os.system("which feroxbuster > /dev/null 2>&1") == 0,
    }

    return jsonify(
        {
            "status": "healthy",
            "tools_status": tools,
            "active_sessions": len(session_manager.list_sessions()),
            "pending_jobs": len(job_manager.list_jobs("pending")),
            "running_jobs": len(job_manager.list_jobs("running")),
        }
    )


@app.route("/api/command", methods=["POST"])
def execute_command():
    """Execute a single command (synchronous or async)"""
    try:
        params = request.json
        command = params.get("command", "")
        timeout = params.get("timeout", DEFAULT_TIMEOUT)
        background = params.get("background", False)

        if not command:
            return jsonify({"error": "Command parameter is required"}), 400

        if background:
            job_id = job_manager.submit_job(command, timeout, background=True)
            return jsonify(
                {
                    "job_id": job_id,
                    "message": "Command submitted to background queue",
                    "success": True,
                }
            )
        else:
            result = execute_command_sync(command, timeout)
            return jsonify(result)

    except Exception as e:
        logger.error(f"Error in command endpoint: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/commands/batch", methods=["POST"])
def execute_batch_commands():
    """Execute multiple commands in parallel"""
    try:
        params = request.json
        commands = params.get("commands", [])
        timeout = params.get("timeout", DEFAULT_TIMEOUT)

        if not commands or not isinstance(commands, list):
            return jsonify({"error": "Commands array is required"}), 400

        job_ids = []
        for cmd in commands:
            job_id = job_manager.submit_job(cmd, timeout)
            job_ids.append(job_id)

        return jsonify(
            {
                "job_ids": job_ids,
                "count": len(job_ids),
                "message": "Commands submitted for execution",
                "success": True,
            }
        )

    except Exception as e:
        logger.error(f"Error in batch command endpoint: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/commands/chain", methods=["POST"])
def execute_chain_commands():
    """Execute commands in sequence (chained with &&)"""
    try:
        params = request.json
        commands = params.get("commands", [])
        timeout = params.get("timeout", DEFAULT_TIMEOUT)
        background = params.get("background", False)

        if not commands or not isinstance(commands, list):
            return jsonify({"error": "Commands array is required"}), 400

        # Chain commands with &&
        chained = " && ".join(commands)

        if background:
            job_id = job_manager.submit_job(chained, timeout, background=True)
            return jsonify(
                {
                    "job_id": job_id,
                    "message": "Chained commands submitted",
                    "success": True,
                }
            )
        else:
            result = execute_command_sync(chained, timeout)
            return jsonify(result)

    except Exception as e:
        logger.error(f"Error in chain command endpoint: {str(e)}")
        return jsonify({"error": str(e)}), 500


# ====================== SESSION MANAGEMENT ======================


@app.route("/api/sessions", methods=["GET"])
def list_sessions():
    """List all active sessions"""
    try:
        sessions = session_manager.list_sessions()
        return jsonify({"sessions": sessions, "count": len(sessions)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/sessions", methods=["POST"])
def create_session():
    """Create a new shell session"""
    try:
        params = request.json or {}
        shell = params.get("shell", "/bin/bash")
        session_id = params.get("session_id")

        sid = session_manager.create_session(session_id, shell)
        return jsonify({"session_id": sid, "success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/sessions/<session_id>", methods=["DELETE"])
def close_session(session_id):
    """Close a session"""
    try:
        success = session_manager.close_session(session_id)
        if success:
            return jsonify({"success": True, "message": "Session closed"})
        else:
            return jsonify({"error": "Session not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/sessions/<session_id>/execute", methods=["POST"])
def execute_in_session(session_id):
    """Execute command in existing session"""
    try:
        params = request.json
        command = params.get("command", "")
        timeout = params.get("timeout", 30)

        if not command:
            return jsonify({"error": "Command is required"}), 400

        result = session_manager.execute_in_session(session_id, command, timeout)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ====================== JOB MANAGEMENT ======================


@app.route("/api/jobs", methods=["GET"])
def list_jobs():
    """List all jobs"""
    try:
        status = request.args.get("status")
        jobs = job_manager.list_jobs(status)
        return jsonify({"jobs": jobs, "count": len(jobs)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/jobs/<job_id>", methods=["GET"])
def get_job(job_id):
    """Get job status and results"""
    try:
        job = job_manager.get_job(job_id)
        if job:
            return jsonify(job)
        else:
            return jsonify({"error": "Job not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/jobs/<job_id>", methods=["DELETE"])
def cancel_job(job_id):
    """Cancel a job"""
    try:
        success = job_manager.cancel_job(job_id)
        if success:
            return jsonify({"success": True, "message": "Job cancelled"})
        else:
            return jsonify({"error": "Job not found or cannot be cancelled"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ====================== ADVANCED TOOLS ======================


@app.route("/api/tools/nmap", methods=["POST"])
def nmap_scan():
    """Execute Nmap scan"""
    try:
        params = request.json
        target = params.get("target", "")
        scan_type = params.get("scan_type", "-sCV")
        ports = params.get("ports", "")
        additional_args = params.get("additional_args", "-T4 -Pn")
        timeout = params.get("timeout", 3600)
        background = params.get("background", False)

        if not target:
            return jsonify({"error": "Target is required"}), 400

        command = f"nmap {scan_type}"
        if ports:
            command += f" -p {ports}"
        if additional_args:
            command += f" {additional_args}"
        command += f" {target}"

        if background:
            job_id = job_manager.submit_job(command, timeout, background=True)
            return jsonify({"job_id": job_id, "success": True})
        else:
            result = execute_command_sync(command, timeout)
            return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/tools/nuclei", methods=["POST"])
def nuclei_scan():
    """Execute Nuclei vulnerability scanner"""
    try:
        params = request.json
        target = params.get("target", "")
        templates = params.get("templates", "")
        severity = params.get("severity", "")
        additional_args = params.get("additional_args", "")
        timeout = params.get("timeout", 3600)
        background = params.get("background", False)

        if not target:
            return jsonify({"error": "Target is required"}), 400

        command = f"nuclei -u {target}"
        if templates:
            command += f" -t {templates}"
        if severity:
            command += f" -severity {severity}"
        if additional_args:
            command += f" {additional_args}"

        if background:
            job_id = job_manager.submit_job(command, timeout, background=True)
            return jsonify({"job_id": job_id, "success": True})
        else:
            result = execute_command_sync(command, timeout)
            return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/tools/ffuf", methods=["POST"])
def ffuf_scan():
    """Execute FFUF web fuzzer (modern alternative to gobuster/nikto)"""
    try:
        params = request.json
        url = params.get("url", "")
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        keyword = params.get("keyword", "FUZZ")
        additional_args = params.get("additional_args", "-mc all -fc 404")
        timeout = params.get("timeout", 1800)
        background = params.get("background", False)

        if not url:
            return jsonify({"error": "URL is required"}), 400

        # Replace FUZZ keyword in URL
        if keyword not in url:
            url = url.rstrip("/") + f"/{keyword}"

        command = f"ffuf -u {url} -w {wordlist} {additional_args}"

        if background:
            job_id = job_manager.submit_job(command, timeout, background=True)
            return jsonify({"job_id": job_id, "success": True})
        else:
            result = execute_command_sync(command, timeout)
            return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/tools/feroxbuster", methods=["POST"])
def feroxbuster_scan():
    """Execute Feroxbuster (modern recursive directory scanner)"""
    try:
        params = request.json
        url = params.get("url", "")
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        additional_args = params.get("additional_args", "-k")
        timeout = params.get("timeout", 1800)
        background = params.get("background", False)

        if not url:
            return jsonify({"error": "URL is required"}), 400

        command = f"feroxbuster -u {url} -w {wordlist} {additional_args}"

        if background:
            job_id = job_manager.submit_job(command, timeout, background=True)
            return jsonify({"job_id": job_id, "success": True})
        else:
            result = execute_command_sync(command, timeout)
            return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/tools/sqlmap", methods=["POST"])
def sqlmap_scan():
    """Execute SQLmap"""
    try:
        params = request.json
        url = params.get("url", "")
        data = params.get("data", "")
        additional_args = params.get("additional_args", "--batch --random-agent")
        timeout = params.get("timeout", 3600)
        background = params.get("background", True)  # SQLmap usually takes long

        if not url:
            return jsonify({"error": "URL is required"}), 400

        command = f"sqlmap -u {url}"
        if data:
            command += f" --data='{data}'"
        command += f" {additional_args}"

        if background:
            job_id = job_manager.submit_job(command, timeout, background=True)
            return jsonify({"job_id": job_id, "success": True})
        else:
            result = execute_command_sync(command, timeout)
            return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/tools/hydra", methods=["POST"])
def hydra_attack():
    """Execute Hydra brute force"""
    try:
        params = request.json
        target = params.get("target", "")
        service = params.get("service", "")
        username = params.get("username", "")
        username_file = params.get("username_file", "")
        password = params.get("password", "")
        password_file = params.get("password_file", "")
        additional_args = params.get("additional_args", "")
        timeout = params.get("timeout", 3600)
        background = params.get("background", True)

        if not target or not service:
            return jsonify({"error": "Target and service are required"}), 400

        command = f"hydra"

        if username:
            command += f" -l {username}"
        elif username_file:
            command += f" -L {username_file}"

        if password:
            command += f" -p {password}"
        elif password_file:
            command += f" -P {password_file}"

        if additional_args:
            command += f" {additional_args}"

        command += f" {service}://{target}"

        if background:
            job_id = job_manager.submit_job(command, timeout, background=True)
            return jsonify({"job_id": job_id, "success": True})
        else:
            result = execute_command_sync(command, timeout)
            return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/tools/metasploit", methods=["POST"])
def metasploit_run():
    """Execute Metasploit module"""
    try:
        params = request.json
        module = params.get("module", "")
        options = params.get("options", {})
        timeout = params.get("timeout", 3600)
        background = params.get("background", True)

        if not module:
            return jsonify({"error": "Module is required"}), 400

        # Build msfconsole command
        msf_commands = [f"use {module}"]
        for key, value in options.items():
            msf_commands.append(f"set {key} {value}")
        msf_commands.append("run")
        msf_commands.append("exit")

        command_str = "; ".join(msf_commands)
        command = f'msfconsole -q -x "{command_str}"'

        if background:
            job_id = job_manager.submit_job(command, timeout, background=True)
            return jsonify({"job_id": job_id, "success": True})
        else:
            result = execute_command_sync(command, timeout)
            return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/tools/gobuster", methods=["POST"])
def gobuster_scan():
    """Execute Gobuster"""
    try:
        params = request.json
        url = params.get("url", "")
        mode = params.get("mode", "dir")
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        additional_args = params.get("additional_args", "")
        timeout = params.get("timeout", 1800)
        background = params.get("background", False)

        if not url:
            return jsonify({"error": "URL is required"}), 400

        command = f"gobuster {mode} -u {url} -w {wordlist} {additional_args}"

        if background:
            job_id = job_manager.submit_job(command, timeout, background=True)
            return jsonify({"job_id": job_id, "success": True})
        else:
            result = execute_command_sync(command, timeout)
            return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/tools/john", methods=["POST"])
def john_crack():
    """Execute John the Ripper"""
    try:
        params = request.json
        hash_file = params.get("hash_file", "")
        wordlist = params.get("wordlist", "/usr/share/wordlists/rockyou.txt")
        format_type = params.get("format", "")
        additional_args = params.get("additional_args", "")
        timeout = params.get("timeout", 3600)
        background = params.get("background", True)

        if not hash_file:
            return jsonify({"error": "Hash file is required"}), 400

        command = f"john {hash_file} --wordlist={wordlist}"
        if format_type:
            command += f" --format={format_type}"
        if additional_args:
            command += f" {additional_args}"

        if background:
            job_id = job_manager.submit_job(command, timeout, background=True)
            return jsonify({"job_id": job_id, "success": True})
        else:
            result = execute_command_sync(command, timeout)
            return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/tools/wpscan", methods=["POST"])
def wpscan_scan():
    """Execute WPScan"""
    try:
        params = request.json
        url = params.get("url", "")
        additional_args = params.get("additional_args", "--random-agent")
        timeout = params.get("timeout", 1800)
        background = params.get("background", False)

        if not url:
            return jsonify({"error": "URL is required"}), 400

        command = f"wpscan --url {url} {additional_args}"

        if background:
            job_id = job_manager.submit_job(command, timeout, background=True)
            return jsonify({"job_id": job_id, "success": True})
        else:
            result = execute_command_sync(command, timeout)
            return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/tools/enum4linux", methods=["POST"])
def enum4linux_scan():
    """Execute Enum4linux"""
    try:
        params = request.json
        target = params.get("target", "")
        additional_args = params.get("additional_args", "-a")
        timeout = params.get("timeout", 600)
        background = params.get("background", False)

        if not target:
            return jsonify({"error": "Target is required"}), 400

        command = f"enum4linux {additional_args} {target}"

        if background:
            job_id = job_manager.submit_job(command, timeout, background=True)
            return jsonify({"job_id": job_id, "success": True})
        else:
            result = execute_command_sync(command, timeout)
            return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/tools/nikto", methods=["POST"])
def nikto_scan():
    """Execute Nikto (legacy - consider using nuclei or ffuf instead)"""
    try:
        params = request.json
        target = params.get("target", "")
        additional_args = params.get("additional_args", "")
        timeout = params.get("timeout", 1800)
        background = params.get("background", False)

        if not target:
            return jsonify({"error": "Target is required"}), 400

        command = f"nikto -h {target} {additional_args}"

        if background:
            job_id = job_manager.submit_job(command, timeout, background=True)
            return jsonify({"job_id": job_id, "success": True})
        else:
            result = execute_command_sync(command, timeout)
            return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/tools/dirb", methods=["POST"])
def dirb_scan():
    """Execute Dirb (legacy - consider using ffuf or feroxbuster instead)"""
    try:
        params = request.json
        url = params.get("url", "")
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        additional_args = params.get("additional_args", "")
        timeout = params.get("timeout", 1800)
        background = params.get("background", False)

        if not url:
            return jsonify({"error": "URL is required"}), 400

        command = f"dirb {url} {wordlist} {additional_args}"

        if background:
            job_id = job_manager.submit_job(command, timeout, background=True)
            return jsonify({"job_id": job_id, "success": True})
        else:
            result = execute_command_sync(command, timeout)
            return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="Enhanced Kali Linux API Server with Advanced Capabilities"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=API_PORT,
        help=f"API server port (default: {API_PORT})",
    )
    parser.add_argument(
        "--host", type=str, default="0.0.0.0", help="API server host (default: 0.0.0.0)"
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument(
        "--workers",
        type=int,
        default=MAX_WORKERS,
        help=f"Maximum parallel workers (default: {MAX_WORKERS})",
    )
    return parser.parse_args()


def main():
    """Main entry point"""
    args = parse_args()

    if args.debug:
        logger.setLevel(logging.DEBUG)
        app.config["DEBUG"] = True

    logger.info("=" * 60)
    logger.info("Enhanced Kali Linux API Server")
    logger.info("=" * 60)
    logger.info(f"Starting server on {args.host}:{args.port}")
    logger.info(f"Max workers: {args.workers}")
    logger.info(f"Debug mode: {args.debug}")
    logger.info("=" * 60)

    # Start cleanup thread
    def cleanup_thread():
        while True:
            time.sleep(3600)  # Run every hour
            session_manager.cleanup_dead_sessions()
            job_manager.cleanup_old_jobs()

    cleanup = threading.Thread(target=cleanup_thread, daemon=True)
    cleanup.start()

    app.run(host=args.host, port=args.port, threaded=True)


if __name__ == "__main__":
    main()

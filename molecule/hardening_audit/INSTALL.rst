Install Docker and the Python dependencies from ``requirements.txt``, then run:

.. code-block:: shell

   molecule test -s hardening_audit

The scenario creates Debian 13, Ubuntu 24.04 and AlmaLinux 9 containers. It
seeds two known configuration drifts, applies ``os_hardening``, then checks the
item level report before Molecule runs its idempotence check.

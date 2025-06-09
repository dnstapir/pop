Name:          tapir-pop
# NOTE: Version must match VERSION file - validated by Makefile srpm target
Version:       v0.3
Release:       1%{?dist}
Group:         dnstapir/edge
Summary:       DNSTAPIR EDGE Policy Processor
License:       BSD
URL:           https://www.github.com/dnstapir/pop
Source0:       %{name}-%{version}.tar.gz
Source1:       tapir-pop.service
BuildRequires: git
BuildRequires: golang

%description
DNSTAPIR EDGE Policy Processor

%{!?_unitdir: %define _unitdir /usr/lib/systemd/system/}
%{!?_sysusersdir: %define _sysusersdir /usr/lib/sysusers.d/}
%{!?_localstatedir: %define _localstatedir /var/}

%prep
%setup -n %{name}

%build
make

%install
mkdir -p %{buildroot}%{_bindir}
mkdir -p %{buildroot}%{_unitdir}
mkdir -p %{buildroot}%{_sysconfdir}/dnstapir/pop
mkdir -p %{buildroot}%{_localstatedir}/log/dnstapir/ 

install -p -m 0755 %{name} %{buildroot}%{_bindir}/%{name}
install -m 0644 %{SOURCE1} %{buildroot}%{_unitdir}

touch %{buildroot}%{_sysconfdir}/dnstapir/pop/rpz-serial.yaml
touch %{buildroot}%{_localstatedir}/log/dnstapir/tapir-pop.log 
touch %{buildroot}%{_localstatedir}/log/dnstapir/pop-dnsengine.log 
touch %{buildroot}%{_localstatedir}/log/dnstapir/pop-mqtt.log 
touch %{buildroot}%{_localstatedir}/log/dnstapir/pop-policy.log 

%files
%license LICENSE

%attr(0770,tapir-pop,dnstapir) %dir %{_sysconfdir}/dnstapir/pop
%attr(0770,tapir-pop,dnstapir) %dir %{_localstatedir}/log/dnstapir/ 

%attr(0755,tapir-pop,dnstapir) %{_bindir}/%{name}
%attr(0644,tapir-pop,dnstapir) %{_unitdir}/tapir-pop.service

%attr(0660,tapir-pop,dnstapir) %{_sysconfdir}/dnstapir/pop/rpz-serial.yaml
%attr(0660,tapir-pop,dnstapir) %{_localstatedir}/log/dnstapir/tapir-pop.log 
%attr(0660,tapir-pop,dnstapir) %{_localstatedir}/log/dnstapir/pop-dnsengine.log 
%attr(0660,tapir-pop,dnstapir) %{_localstatedir}/log/dnstapir/pop-mqtt.log 
%attr(0660,tapir-pop,dnstapir) %{_localstatedir}/log/dnstapir/pop-policy.log 

%attr(0660,tapir-pop,dnstapir) %ghost %{_sysconfdir}/dnstapir/tapir-pop.yaml
%attr(0660,tapir-pop,dnstapir) %ghost %{_sysconfdir}/dnstapir/pop-sources.yaml
%attr(0660,tapir-pop,dnstapir) %ghost %{_sysconfdir}/dnstapir/pop-policy.yaml
%attr(0660,tapir-pop,dnstapir) %ghost %{_sysconfdir}/dnstapir/pop-outputs.yaml

%pre
/usr/bin/getent group dnstapir || /usr/sbin/groupadd -r dnstapir
/usr/bin/getent passwd tapir-pop || /usr/sbin/useradd -r -d /etc/dnstapir -G dnstapir -s /sbin/nologin tapir-pop

%post

%preun

%postun

%check

%changelog

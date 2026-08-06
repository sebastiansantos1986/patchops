param(
  [string]$ApiUrl = "http://127.0.0.1:3000/api",
  [string]$DeviceId = "lab-windows"
)

Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore

$window = New-Object Windows.Window
$window.Title = "PatchOps Security Update — LAB MODE"
$window.Width = 460
$window.Height = 280
$window.WindowStartupLocation = "CenterScreen"
$window.ResizeMode = "NoResize"

$panel = New-Object Windows.Controls.StackPanel
$panel.Margin = "24"
$title = New-Object Windows.Controls.TextBlock
$title.Text = "Security updates are ready"
$title.FontSize = 22
$title.FontWeight = "Bold"
$message = New-Object Windows.Controls.TextBlock
$message.Text = "Google Chrome and Zoom updates are ready. LAB MODE records your choice only; it will not install software or restart Windows."
$message.TextWrapping = "Wrap"
$message.Margin = "0,12,0,20"
$buttons = New-Object Windows.Controls.StackPanel
$buttons.Orientation = "Horizontal"

$result = $null
foreach ($definition in @(@("Install now", "install_now"), @("Schedule", "schedule"), @("Later", "defer"))) {
  $button = New-Object Windows.Controls.Button
  $button.Content = $definition[0]
  $button.Tag = $definition[1]
  $button.MinWidth = 110
  $button.Height = 36
  $button.Margin = "0,0,10,0"
  $button.Add_Click({ $script:result = $this.Tag; $window.Close() })
  [void]$buttons.Children.Add($button)
}

[void]$panel.Children.Add($title)
[void]$panel.Children.Add($message)
[void]$panel.Children.Add($buttons)
$window.Content = $panel
[void]$window.ShowDialog()

if ($result) {
  $payload = @{ action_id = [guid]::NewGuid().ToString(); notification_id = "lab-security-update"; device_id = $DeviceId; platform = "windows"; action = $result } | ConvertTo-Json
  $response = Invoke-RestMethod -Uri "$ApiUrl/notifications/actions" -Method Post -ContentType "application/json" -Body $payload
  Write-Host "Recorded $($response.action) for $($response.device_id) ($($response.mode) mode)"
}
